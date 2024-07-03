package b2bua

import (
	"fmt"

	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/fcm"
	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/pushkit"
	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/registry"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/auth"
	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
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

type B2BUAConfig struct {
	UserAgent       string
	DisableAuth     bool
	EnableTLS       bool
	EnableWebSocket bool
	EnableRFC8599   bool
	Dns             string
	ListenAddress   string
	UdpPort         int
	TcpPort         int
	TlsPort         int
	WSPort          int
	WSSPort         int
	SSLCert         string
	SSLKey          string
	UdpPortRange    []int
	UaMediaConfig   UserAgentMediaConfig
}

// B2BUA .
type B2BUA struct {
	accounts map[string]string
	registry registry.Registry
	service  *CallService
	rfc8599  *registry.RFC8599
}

var (
	logger      log.Logger
	b2buaConfig *B2BUAConfig
)

func init() {
	logger = utils.NewLogrusLogger(log.DebugLevel, "B2BUA", nil)
	b2buaConfig = &B2BUAConfig{
		UserAgent:       "Go B2BUA/1.0.0",
		DisableAuth:     false,
		EnableWebSocket: false,
		EnableTLS:       false,
		Dns:             "8.8.8.8",
		ListenAddress:   "0.0.0.0",
		UdpPort:         5060,
		TcpPort:         5060,
		TlsPort:         5061,
		WSPort:          8088,
		WSSPort:         8089,
		SSLCert:         "certs/cert.pem",
		SSLKey:          "certs/key.pem",
		UdpPortRange:    []int{60000, 65535},
		UaMediaConfig: UserAgentMediaConfig{
			Codecs:             []string{"PCMU", "PCMA", "opus", "H264", "VP8", "VP9"},
			ExternalRtpAddress: "0.0.0.0",
			RtcpFeedback:       []string{"nack", "nack pli", "ccm fir", "goog-remb", "transport-cc"},
		},
	}
}

// NewB2BUA .
func NewB2BUA(disableAuth bool, enableTLS bool, enableWebSocket bool, enalbeRFC8599 bool) *B2BUA {

	b2buaConfig.DisableAuth = disableAuth
	b2buaConfig.EnableTLS = enableTLS
	b2buaConfig.EnableWebSocket = enableWebSocket
	b2buaConfig.EnableRFC8599 = enalbeRFC8599

	memRegistry := registry.Registry(registry.NewMemoryRegistry())

	b := &B2BUA{
		registry: memRegistry,
		accounts: make(map[string]string),
	}

	if b2buaConfig.EnableRFC8599 {
		b.rfc8599 = registry.NewRFC8599(pushCallback)
		logger.Infof("RFC8599 enabled")
	}

	var authenticator *auth.ServerAuthorizer = nil

	if !b2buaConfig.DisableAuth {
		authenticator = auth.NewServerAuthorizer(b.requestCredential, "b2bua", false)
	} else {
		logger.Warn("Auth disabled")
	}

	stack := stack.NewSipStack(&stack.SipStackConfig{
		UserAgent:  b2buaConfig.UserAgent,
		Extensions: []string{"replaces", "outbound"},
		Dns:        b2buaConfig.Dns,
		ServerAuthManager: stack.ServerAuthManager{
			Authenticator:     authenticator,
			RequiresChallenge: b.requiresChallenge,
		},
	})

	stack.OnConnectionError(b.handleConnectionError)

	var listenAddress = fmt.Sprintf("%s:%d", b2buaConfig.ListenAddress, b2buaConfig.UdpPort)

	if err := stack.Listen("udp", listenAddress); err != nil {
		logger.Panic(err)
	}
	logger.Infof("listening on: udp://%s", listenAddress)

	listenAddress = fmt.Sprintf("%s:%d", b2buaConfig.ListenAddress, b2buaConfig.TcpPort)
	if err := stack.Listen("tcp", listenAddress); err != nil {
		logger.Panic(err)
	}

	logger.Infof("listening on: tcp://%s", listenAddress)

	if b2buaConfig.EnableWebSocket {
		listenAddress = fmt.Sprintf("%s:%d", b2buaConfig.ListenAddress, b2buaConfig.WSPort)
		if err := stack.Listen("ws", listenAddress); err != nil {
			logger.Panic(err)
		}
		logger.Infof("listening on: ws://%s", listenAddress)
	}

	if b2buaConfig.EnableTLS {

		logger.Infof("TLS enabled: %s, %s", b2buaConfig.SSLCert, b2buaConfig.SSLKey)
		tlsOptions := &transport.TLSConfig{Cert: b2buaConfig.SSLCert, Key: b2buaConfig.SSLKey}

		listenAddress = fmt.Sprintf("%s:%d", b2buaConfig.ListenAddress, b2buaConfig.TlsPort)
		if err := stack.ListenTLS("tls", listenAddress, tlsOptions); err != nil {
			logger.Panic(err)
		}

		logger.Infof("listening on: tls://%s", listenAddress)
		if b2buaConfig.EnableWebSocket {
			listenAddress = fmt.Sprintf("%s:%d", b2buaConfig.ListenAddress, b2buaConfig.WSSPort)
			if err := stack.ListenTLS("wss", "0.0.0.0:8089", tlsOptions); err != nil {
				logger.Panic(err)
			}
			logger.Infof("listening on: wss://%s", listenAddress)
		}
	}

	ua := ua.NewUserAgent(&ua.UserAgentConfig{
		SipStack: stack,
	})

	ua.RegisterStateHandler = b.registerStateHandler
	stack.OnRequest(sip.REGISTER, b.handleRegister)

	b.service = NewCallService(stack, ua, memRegistry, b.rfc8599)
	ua.InviteStateHandler = b.service.inviteStateHandler
	return b
}

func (b *B2BUA) registerStateHandler(state account.RegisterState) {
	logger.Infof("RegisterStateHandler: state => %v", state)
}

func (b *B2BUA) BridgedCalls() []*CallBridge {
	return b.service.callBridges
}

// Originate .
func (b *B2BUA) Originate(source string, destination string) {
	b.service.Originate(source, destination)
}

// Shutdown .
func (b *B2BUA) Shutdown() {
	b.service.Shutdown()
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
