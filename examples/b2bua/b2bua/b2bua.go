package b2bua

import (
	"fmt"

	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/fcm"
	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/pushkit"
	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/registry"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/auth"
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
	"github.com/ghettovoice/gosip/transport"
)

func pushCallback(pn *registry.PNParams, payload map[string]string) error {
	fmt.Printf("Handle Push Request:\nprovider=%v\nparam=%v\nprid=%v\npayload=%v", pn.Provider, pn.Param, pn.PRID, payload)
	switch pn.Provider {
	case "apns":
		go pushkit.DoPushKit("./voip-callkeep.p12", pn.PRID, payload)
		return nil
	case "fcm":
		go fcm.FCMPush("service-account.json", pn.PRID, payload)
		return nil
	}
	return fmt.Errorf("%v provider not found", pn.Provider)
}

// B2BUA .
type B2BUA struct {
	stack       *stack.SipStack
	ua          *ua.UserAgent
	accounts    map[string]string
	registry    registry.Registry
	callBridges []*CallBridge
	calls       map[*session.Session]*Call
	rfc8599     *registry.RFC8599
}

var (
	logger     log.Logger
	callConfig CallConfig
)

func init() {
	logger = utils.NewLogrusLogger(utils.DefaultLogLevel, "B2BUA", nil)
	callConfig = CallConfig{
		Codecs:             []string{"PCMU", "PCMA", "opus", "H264"},
		ExternalRtpAddress: "0.0.0.0",
		RtcpFeedback:       []string{"nack", "nack pli", "ccm fir", "goog-remb", "transport-cc"},
	}
}

// NewB2BUA .
func NewB2BUA(disableAuth bool, enableTLS bool) *B2BUA {
	b := &B2BUA{
		registry: registry.Registry(registry.NewMemoryRegistry()),
		accounts: make(map[string]string),
		rfc8599:  registry.NewRFC8599(pushCallback),
		calls:    make(map[*session.Session]*Call),
	}

	var authenticator *auth.ServerAuthorizer = nil

	if !disableAuth {
		authenticator = auth.NewServerAuthorizer(b.requestCredential, "b2bua", false)
	}

	stack := stack.NewSipStack(&stack.SipStackConfig{
		UserAgent:  "Go B2BUA/1.0.0",
		Extensions: []string{"replaces", "outbound"},
		Dns:        "8.8.8.8",
		ServerAuthManager: stack.ServerAuthManager{
			Authenticator:     authenticator,
			RequiresChallenge: b.requiresChallenge,
		},
	})

	stack.OnConnectionError(b.handleConnectionError)

	if err := stack.Listen("udp", "0.0.0.0:5060"); err != nil {
		logger.Panic(err)
	}

	if err := stack.Listen("tcp", "0.0.0.0:5060"); err != nil {
		logger.Panic(err)
	}

	if enableTLS {
		tlsOptions := &transport.TLSConfig{Cert: "certs/cert.pem", Key: "certs/key.pem"}

		if err := stack.ListenTLS("tls", "0.0.0.0:5061", tlsOptions); err != nil {
			logger.Panic(err)
		}

		if err := stack.ListenTLS("wss", "0.0.0.0:8089", tlsOptions); err != nil {
			logger.Panic(err)
		}
	}

	ua := ua.NewUserAgent(&ua.UserAgentConfig{
		SipStack: stack,
	})

	ua.InviteStateHandler = func(sess *session.Session, req *sip.Request, resp *sip.Response, state session.Status) {
		logger.Infof("InviteStateHandler: state => %v, type => %s", state, sess.Direction())

		switch state {
		// Handle outgoing call.
		case session.InviteSent:

		// Handle incoming call.
		case session.InviteReceived:
			to, _ := (*req).To()
			from, _ := (*req).From()
			caller := from.Address
			called := to.Address

			doInvite := func(instance *registry.ContactInstance) {
				displayName := ""
				if from.DisplayName != nil {
					displayName = from.DisplayName.String()
				}

				offer := &Desc{Type: "offer", SDP: sess.RemoteSdp()}
				sdpSess, _ := offer.Parse()
				transType := ParseTransportType(sdpSess)

				trackInfos, err := ParseTrackInfos(sdpSess)
				if err != nil {
					logger.Errorf("ParseTrackInfos error: %v", err)
					return
				}

				src := &Call{sess: sess}
				src.Init(transType, trackInfos)
				src.OnOffer(offer)
				b.calls[sess] = src

				// Create a temporary profile. In the future, it will support reading profiles from files or data
				// For example: use a specific ip or sip account as outbound trunk
				profile := account.NewProfile(caller, displayName, nil, 0, stack)

				recipient, err2 := parser.ParseSipUri("sip:" + called.User().String() + "@" + instance.Source + ";transport=" + instance.Transport)
				if err2 != nil {
					logger.Error(err2)
				}
				var tpType = TransportTypeStandard
				if instance.SupportIce() {
					tpType = TransportTypeWebRTC
				}

				dest := &Call{}
				dest.Init(tpType, trackInfos)
				destOffer, _ := dest.CreateOffer()

				dsess, err := ua.Invite(profile, called, recipient, &destOffer.SDP)
				if err != nil {
					logger.Errorf("B-Leg session error: %v", err)
					return
				}

				dest.sess = dsess
				b.calls[dsess] = dest

				bridge := &CallBridge{src: src, dest: dest, bType: B2BCall}
				bridge.Init()
				bridge.SetState(Connecting)
				b.callBridges = append(b.callBridges, bridge)
			}

			// Try to find online contact records.
			if contacts, found := b.registry.GetContacts(called); found {
				sess.Provisional(100, "Trying")
				for _, instance := range *contacts {
					doInvite(instance)
				}
				return
			}

			// Pushable: try to find pn-params in contact records.
			// Try to push the UA and wait for it to wake up.
			pusher, ok := b.rfc8599.TryPush(called, from)
			if ok {
				sess.Provisional(100, "Trying")
				instance, err := pusher.WaitContactOnline()
				if err != nil {
					logger.Errorf("Push failed, error: %v", err)
					sess.Reject(500, "Push failed")
					return
				}
				doInvite(instance)
				return
			}

			logger.Warnf("Not found any records for %v", called)
			// Could not found any records
			sess.Reject(404, fmt.Sprintf("%v Not found", called))

		// Handle re-INVITE or UPDATE.
		case session.ReInviteReceived:
			logger.Infof("re-INVITE")
			switch sess.Direction() {
			case session.Incoming:
				sess.Accept(200)
			case session.Outgoing:
				//TODO: Need to provide correct answer.
			}

		// Handle 1XX
		case session.EarlyMedia:
			//bridge.SetState(EarlyMedia)
			//bridge.src.Provisional((*resp).StatusCode(), (*resp).Reason())
		case session.Provisional:
			call := b.findCall(sess)
			if call != nil {
				//answer := call.dest.RemoteSdp()
				//call.OnAnswer(&Desc{Type: "answer", SDP: answer})
			}
		// Handle 200OK or ACK
		case session.Confirmed:
			//TODO: Add support for forked calls
			call := b.findCall(sess)
			if call != nil && sess.Direction() == session.Outgoing {
				answer := call.sess.RemoteSdp()
				call.OnAnswer(&Desc{Type: "answer", SDP: answer})
				bridge := b.findBridgedCall(sess)
				if bridge != nil && bridge.dest.sess == sess && bridge.bType == B2BCall {
					bridge.dest.OnAnswer(&Desc{Type: "answer", SDP: answer})
					bridge.src.Accept(answer)
					BridgeMediaStream(bridge.src.mediaTransport, bridge.dest.mediaTransport)
					bridge.SetState(Confirmed)
				}
			}

		// Handle 4XX+
		case session.Failure:
			fallthrough
		case session.Canceled:
			fallthrough
		case session.Terminated:
			//TODO: Add support for forked calls
			bridge := b.findBridgedCall(sess)
			call := b.findCall(sess)
			if bridge != nil && call != nil {
				bridge.Terminate(call)
			}
			b.removeCall(sess)
			b.removeCallBridge(sess)
		}
	}

	ua.RegisterStateHandler = func(state account.RegisterState) {
		logger.Infof("RegisterStateHandler: state => %v", state)
	}

	stack.OnRequest(sip.REGISTER, b.handleRegister)
	b.stack = stack
	b.ua = ua
	return b
}

func (b *B2BUA) findCall(sess *session.Session) *Call {
	if call, found := b.calls[sess]; found {
		return call
	}
	return nil
}

func (b *B2BUA) removeCall(sess *session.Session) {
	delete(b.calls, sess)
}

func (b *B2BUA) BridgedCalls() []*CallBridge {
	return b.callBridges
}

func (b *B2BUA) findBridgedCall(sess *session.Session) *CallBridge {
	for _, call := range b.callBridges {
		if call.src.sess == sess || call.dest.sess == sess {
			return call
		}
	}
	return nil
}

func (b *B2BUA) removeCallBridge(sess *session.Session) {
	for idx, call := range b.callBridges {
		if call.src.sess == sess || call.dest.sess == sess {
			b.callBridges = append(b.callBridges[:idx], b.callBridges[idx+1:]...)
			return
		}
	}
}

// Originate .
func (b *B2BUA) Originate(source string, destination string) {
	logger.Infof("Originate %s => %s", source, destination)
	/*
		doInvite := func(recipient sip.SipUri, tpType TransportType) {
			displayName := ""
			caller, _ := parser.ParseUri("sip:" + source)
			call := &CallBridge{}

			call.Init()

			offer := sess.RemoteSdp()
			call.SetALegOffer(&Desc{Type: "offer", SDP: offer})

			// Create a temporary profile. In the future, it will support reading profiles from files or data
			// For example: use a specific ip or sip account as outbound trunk
			profile := account.NewProfile(caller, displayName, nil, 0, b.stack)

			bLegOffer, _ := call.CreateBLegOffer(tpType)

			dest, err := b.ua.Invite(profile, caller, recipient, &bLegOffer.SDP)
			if err != nil {
				logger.Errorf("Can't send invite, error: %v", err)
				return
			}

			call.dest = dest
		}

		srcUri, err := parser.ParseUri("sip:" + source)
		if err != nil {
			logger.Error(err)
			return
		}

		destUri, err := parser.ParseSipUri("sip:" + destination)
		if err != nil {
			logger.Error(err)
			return
		}

		// Try to find online contact records.
		if contacts, found := b.registry.GetContacts(srcUri); found {
			for _, instance := range *contacts {
				var tpType = TransportTypeSIP
				if instance.SupportIce() {
					tpType = TransportTypeRTC
				}
				recipient, err2 := parser.ParseSipUri("sip:" + instance.Contact.Address.User().String() + "@" + instance.Source + ";transport=" + instance.Transport)
				if err2 != nil {
					logger.Error(err2)
				}
				doInvite(recipient, tpType)
			}
			return
		}*/
}

// Shutdown .
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

// AddAccount .
func (b *B2BUA) AddAccount(username string, password string) {
	b.accounts[username] = password
}

// GetAccounts .
func (b *B2BUA) GetAccounts() map[string]string {
	return b.accounts
}

// GetRegistry .
func (b *B2BUA) GetRegistry() registry.Registry {
	return b.registry
}

// GetRFC8599 .
func (b *B2BUA) GetRFC8599() *registry.RFC8599 {
	return b.rfc8599
}

func (b *B2BUA) requestCredential(username string) (string, string, error) {
	if password, found := b.accounts[username]; found {
		logger.Infof("Found user %s", username)
		return password, "", nil
	}
	return "", "", fmt.Errorf("username [%s] not found", username)
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
		b.rfc8599.HandleContactInstance(aor, instance)
	} else {
		logger.Infof("Logged out [%v] expires [%d] ", to, expires)
		reason = "UnRegistered"
		instance := registry.NewContactInstanceForRequest(request)
		b.registry.RemoveContact(aor, instance)
		b.rfc8599.HandleContactInstance(aor, instance)
	}

	resp := sip.NewResponseFromRequest(request.MessageID(), request, 200, reason, "")
	sip.CopyHeaders("Expires", request, resp)
	utils.BuildContactHeader("Contact", request, resp, &expires)
	tx.Respond(resp)
}

func (b *B2BUA) handleConnectionError(connError *transport.ConnectionError) {
	logger.Debugf("Handle Connection Lost: Source: %v, Dest: %v, Network: %v", connError.Source, connError.Dest, connError.Net)
	b.registry.HandleConnectionError(connError)
}

func (b *B2BUA) SetLogLevel(level log.Level) {
	utils.SetLogLevel("B2BUA", level)
}
