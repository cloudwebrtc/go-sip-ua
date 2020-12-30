package b2bua

import (
	"fmt"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/auth"
	"github.com/cloudwebrtc/go-sip-ua/pkg/endpoint"
	"github.com/cloudwebrtc/go-sip-ua/pkg/invite"
	"github.com/cloudwebrtc/go-sip-ua/pkg/registry"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	utils "github.com/cloudwebrtc/go-sip-ua/pkg/util"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
	"github.com/ghettovoice/gosip/transport"
	sdp "github.com/pixelbender/go-sdp/sdp"
)

type B2BCall struct {
	source *invite.Session
	dest   *invite.Session
}

// B2BUA .
type B2BUA struct {
	ua       *ua.UserAgent
	accounts map[string]string
	registry registry.Registry
	domains  []string
	sessions []*B2BCall
}

var (
	logger log.Logger
)

func init() {
	logger = log.NewDefaultLogrusLogger().WithPrefix("B2BUA")
}

//NewB2BUA .
func NewB2BUA() *B2BUA {
	b := &B2BUA{
		registry: registry.Registry(&*registry.NewMemoryRegistry()),
		accounts: make(map[string]string),
	}

	endpoint := endpoint.NewEndPoint(&endpoint.EndPointConfig{
		Extensions: []string{"replaces", "outbound"},
		Dns:        "8.8.8.8",
		ServerAuthManager: endpoint.ServerAuthManager{
			Authenticator:     auth.NewServerAuthorizer(b.requestCredential, false, logger),
			RequiresChallenge: b.requiresChallenge,
		},
	}, logger)

	if err := endpoint.Listen("udp", "0.0.0.0:5060", nil); err != nil {
		logger.Panic(err)
	}

	if err := endpoint.Listen("tcp", "0.0.0.0:5070", nil); err != nil {
		logger.Panic(err)
	}

	tlsOptions := &transport.Options{CertFile: "certs/cert.pem", KeyFile: "certs/key.pem"}

	if err := endpoint.Listen("tls", "0.0.0.0:5061", tlsOptions); err != nil {
		logger.Panic(err)
	}

	if err := endpoint.Listen("wss", "0.0.0.0:5081", tlsOptions); err != nil {
		logger.Panic(err)
	}

	ua := ua.NewUserAgent(&ua.UserAgentConfig{
		UserAgent: "Go B2BUA/1.0.0",
		Endpoint:  endpoint,
	}, logger)

	ua.InviteStateHandler = func(sess *invite.Session, req *sip.Request, resp *sip.Response, state invite.Status) {
		logger.Infof("InviteStateHandler: state => %v, type => %s", state, sess.Direction())

		switch state {
		// Received incoming call.
		case invite.InviteReceived:
			to, _ := (*req).To()
			from, _ := (*req).From()
			aor := to.Address
			contacts, err := b.registry.GetContacts(aor)
			if err != nil {
				sess.Reject(404, fmt.Sprintf("%v Not found", aor))
				return
			}
			sess.Provisional(100, "Trying")
			for _, instance := range *contacts {
				displayName := ""
				if from.DisplayName != nil {
					displayName = from.DisplayName.String()
				}
				profile := account.NewProfile(from.Address.User().String(), displayName, nil, 0)
				target, err := parser.ParseSipUri("sip:" + aor.User().String() + "@" + instance.Source + ";transport=" + instance.Transport)
				if err != nil {
					logger.Error(err)
				}
				sdp := (*req).Body()
				dest, err := ua.Invite(profile, target, &sdp)
				if err != nil {
					logger.Errorf("B leg session error: %v", err)
					return
				}

				b2bCall := &B2BCall{source: sess, dest: dest}
				b.sessions = append(b.sessions, b2bCall)
			}
		case invite.Failure:
			fallthrough
		case invite.Canceled:
			fallthrough
		case invite.Terminated:
			call := b.findB2BCall(sess)
			if call != nil {
				if call.source == sess {
					call.dest.End()
				} else if call.dest == sess {
					call.source.End()
				}
			}
			b.deleteB2BCall(sess)
			break
		case invite.EarlyMedia:
			fallthrough
		case invite.Provisional:
			call := b.findB2BCall(sess)
			if call != nil && call.dest == sess {
				body := (*req).Body()
				if len(body) > 0 {
					answer, _ := sdp.ParseString(body)
					call.source.ProvideAnswer(answer)
				}
				call.source.Provisional((*resp).StatusCode(), (*resp).Reason())
			}
			break
		case invite.Confirmed:
			body := (*req).Body()
			logger.Infof("invite.Confirmed: sdp => %v", body)
			call := b.findB2BCall(sess)
			if call != nil && call.dest == sess {
				answer, _ := sdp.ParseString(body)
				call.source.ProvideAnswer(answer)
				call.source.Accept(200)
			}
			break
		}
		/*
			if state == invite.Offer {
				sess.ProvideAnswer(answer)
				sess.Accept(200)
			}

			if state == invite.InviteReceived {
				sess.Provisional(180, "Ringing")
				sess.ProvideAnswer(answer)
				sess.Accept(200)
			}
		*/
	}

	ua.RegisterStateHandler = func(state account.RegisterState) {
		logger.Infof("RegisterStateHandler: state => %v", state)
	}

	endpoint.OnRequest(sip.REGISTER, b.handleRegister)
	b.ua = ua
	return b
}

func (b *B2BUA) findB2BCall(sess *invite.Session) *B2BCall {
	for _, call := range b.sessions {
		if call.source == sess || call.dest == sess {
			return call
		}
	}
	return nil
}

func (b *B2BUA) deleteB2BCall(sess *invite.Session) {
	for idx, call := range b.sessions {
		if call.source == sess || call.dest == sess {
			b.sessions = append(b.sessions[:idx], b.sessions[idx+1:]...)
			return
		}
	}
}

//Shutdown .
func (b *B2BUA) Shutdown() {
	b.ua.Shutdown()
}

func (b *B2BUA) requiresChallenge(req sip.Request) bool {
	switch req.Method() {
	//case sip.UPDATE:
	case sip.REGISTER:
		return true
	case sip.INVITE:
		return true
	//case sip.RREFER:
	//	return false
	case sip.CANCEL:
		return false
	case sip.OPTIONS:
		return false
	case sip.INFO:
		return false
	case sip.BYE:
		{
			// Allow locally initiated dialogs
			// Return false if call-id in sessions.
			return false
		}
	}
	return false
}

//AddAccount .
func (b *B2BUA) AddAccount(username string, password string) {
	b.accounts[username] = password
}

//GetAccounts .
func (b *B2BUA) GetAccounts() map[string]string {
	return b.accounts
}

//GetRegistry .
func (b *B2BUA) GetRegistry() registry.Registry {
	return b.registry
}

func (b *B2BUA) requestCredential(username string) (string, error) {
	if password, found := b.accounts[username]; found {
		logger.Infof("Found user %s", username)
		return password, nil
	}
	return "", fmt.Errorf("username [%s] not found", username)
}

func (b *B2BUA) handleRegister(request sip.Request, tx sip.ServerTransaction) {
	headers := request.GetHeaders("Expires")
	to, _ := request.To()
	aor := to.Address.Clone()
	var expires sip.Expires = 0
	if len(headers) > 0 {
		expires = *headers[0].(*sip.Expires)
	}

	reason := ""
	if len(headers) > 0 && expires != sip.Expires(0) {
		instance := registry.NewContactInstanceForRequest(request)
		logger.Infof("Registered [%v] expires [%d] source %s", to, expires, request.Source())
		reason = "Registered"
		b.registry.AddAor(aor, instance)
	} else {
		logger.Infof("Logged out [%v] expires [%d] ", to, expires)
		reason = "Unregistered"
		instance := registry.NewContactInstanceForRequest(request)
		b.registry.RemoveContact(aor, instance)
	}

	resp := sip.NewResponseFromRequest(request.MessageID(), request, 200, reason, "")
	sip.CopyHeaders("Expires", request, resp)
	utils.BuildContactHeader("Contact", request, resp, &expires)
	sip.CopyHeaders("Content-Length", request, resp)
	tx.Respond(resp)

}
