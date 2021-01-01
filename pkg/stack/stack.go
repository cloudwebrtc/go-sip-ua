package stack

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwebrtc/go-sip-ua/pkg/auth"
	utils "github.com/cloudwebrtc/go-sip-ua/pkg/util"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/transaction"
	"github.com/ghettovoice/gosip/transport"
	"github.com/ghettovoice/gosip/util"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultUserAgent .
	DefaultUserAgent = "Go SipStack/1.0.0"
)

// RequestHandler is a callback that will be called on the incoming request
// of the certain method
// tx argument can be nil for 2xx ACK request
type RequestHandler func(req sip.Request, tx sip.ServerTransaction)

// RequiresChallengeHandler will check if each request requires 401/407 authentication.
type RequiresChallengeHandler func(req sip.Request) bool

// ServerAuthManager .
type ServerAuthManager struct {
	Authenticator     *auth.ServerAuthorizer
	RequiresChallenge RequiresChallengeHandler
}

// SipStackConfig describes available options
type SipStackConfig struct {
	// Public IP address or domain name, if empty auto resolved IP will be used.
	Host string
	// Dns is an address of the public DNS server to use in SRV lookup.
	Dns               string
	Extensions        []string
	MsgMapper         sip.MessageMapper
	ServerAuthManager ServerAuthManager
}

// SipStack a golang SIP Stack
type SipStack struct {
	listenPorts     map[string]*sip.Port
	tp              transport.Layer
	tx              transaction.Layer
	host            string
	ip              net.IP
	inShutdown      int32
	hwg             *sync.WaitGroup
	hmu             *sync.RWMutex
	requestHandlers map[sip.RequestMethod]RequestHandler
	extensions      []string
	invites         map[transaction.TxKey]sip.Request
	invitesLock     *sync.RWMutex
	authenticator   *ServerAuthManager
	log             log.Logger
}

// NewSipStack creates new instance of SipStack.
func NewSipStack(config *SipStackConfig, logger log.Logger) *SipStack {
	if config == nil {
		config = &SipStackConfig{}
	}

	logger = logger.WithPrefix("SipStack")

	var host string
	var ip net.IP
	if config.Host != "" {
		host = config.Host
		if addr, err := net.ResolveIPAddr("ip", host); err == nil {
			ip = addr.IP
		} else {
			logger.Panicf("resolve host IP failed: %s", err)
		}
	} else {
		if v, err := util.ResolveSelfIP(); err == nil {
			ip = v
			host = v.String()
		} else {
			logger.Panicf("resolve host IP failed: %s", err)
		}
	}

	var dnsResolver *net.Resolver
	if config.Dns != "" {
		dnsResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", config.Dns)
			},
		}
	} else {
		dnsResolver = net.DefaultResolver
	}

	var extensions []string
	if config.Extensions != nil {
		extensions = config.Extensions
	}

	gs := &SipStack{
		listenPorts:     make(map[string]*sip.Port),
		host:            host,
		ip:              ip,
		hwg:             new(sync.WaitGroup),
		hmu:             new(sync.RWMutex),
		requestHandlers: make(map[sip.RequestMethod]RequestHandler),
		extensions:      extensions,
		invites:         make(map[transaction.TxKey]sip.Request),
		invitesLock:     new(sync.RWMutex),
	}

	if config.ServerAuthManager.Authenticator != nil {
		gs.authenticator = &config.ServerAuthManager
	}

	gs.log = logger.WithFields(log.Fields{
		"sip_server_ptr": fmt.Sprintf("%p", gs),
	})
	gs.tp = transport.NewLayer(ip, dnsResolver, config.MsgMapper, gs.Log())
	gs.tx = transaction.NewLayer(gs.tp, utils.NewLogrusLogger(logrus.ErrorLevel) /*gs.Log().WithFields(gs.tp.Log().Fields())*/)

	go gs.serve()

	return gs
}

// Log .
func (gs *SipStack) Log() log.Logger {
	return gs.log
}

// Listen ListenAndServe starts serving listeners on the provided address
func (gs *SipStack) Listen(protocol string, listenAddr string, options *transport.TLSConfig) error {
	network := strings.ToUpper(protocol)
	err := gs.tp.Listen(network, listenAddr, options)
	if err == nil {
		target, err := transport.NewTargetFromAddr(listenAddr)
		if err != nil {
			return err
		}
		target = transport.FillTargetHostAndPort(network, target)
		if _, ok := gs.listenPorts[network]; !ok {
			gs.listenPorts[network] = target.Port
		}
	}
	return err
}

func (gs *SipStack) serve() {
	defer gs.Shutdown()

	for {
		select {
		case tx, ok := <-gs.tx.Requests():
			if !ok {
				return
			}
			gs.hwg.Add(1)
			go gs.handleRequest(tx.Origin(), tx)
		case ack, ok := <-gs.tx.Acks():
			if !ok {
				return
			}
			gs.hwg.Add(1)
			go gs.handleRequest(ack, nil)
		case response, ok := <-gs.tx.Responses():
			if !ok {
				return
			}
			logger := gs.Log().WithFields(map[string]interface{}{
				"sip_response": response.Short(),
			})
			logger.Warn("received not matched response")
			if key, err := transaction.MakeClientTxKey(response); err == nil {
				gs.invitesLock.RLock()
				inviteRequest, ok := gs.invites[key]
				gs.invitesLock.RUnlock()
				if ok {
					go gs.AckInviteRequest(inviteRequest, response)
				}
			}
		case err, ok := <-gs.tx.Errors():
			if !ok {
				return
			}
			gs.Log().Errorf("received SIP transaction error: %s", err)
		case err, ok := <-gs.tp.Errors():
			if !ok {
				return
			}

			gs.Log().Errorf("received SIP transport error: %s", err)
		}
	}
}

func (gs *SipStack) handleRequest(req sip.Request, tx sip.ServerTransaction) {
	defer gs.hwg.Done()

	logger := gs.Log().WithFields(req.Fields())
	logger.Info("routing incoming SIP request...")

	gs.hmu.RLock()
	handler, ok := gs.requestHandlers[req.Method()]
	gs.hmu.RUnlock()

	if !ok {
		logger.Warnf("SIP request handler not found")

		res := sip.NewResponseFromRequest("", req, 405, "Method Not Allowed", "")
		if _, err := gs.Respond(res); err != nil {
			logger.Errorf("respond '405 Method Not Allowed' failed: %s", err)
		}

		return
	}

	if gs.authenticator != nil {
		authenticator := gs.authenticator.Authenticator
		requiresChallenge := gs.authenticator.RequiresChallenge
		if requiresChallenge(req) == true {
			go func() {
				if _, ok := authenticator.Authenticate(req, tx); ok {
					handler(req, tx)
				}
			}()
			return
		}
	}

	go handler(req, tx)
}

//Request Send SIP message
func (gs *SipStack) Request(req sip.Request) (sip.ClientTransaction, error) {
	if gs.shuttingDown() {
		return nil, fmt.Errorf("can not send through stopped server")
	}

	return gs.tx.Request(gs.prepareRequest(req))
}

func (gs SipStack) GetNetworkInfo(protocol string) *transport.Target {
	logger := gs.Log()

	var target transport.Target
	if v, err := util.ResolveSelfIP(); err == nil {
		target.Host = v.String()
	} else {
		logger.Panicf("resolve host IP failed: %s", err)
	}

	network := strings.ToUpper(protocol)
	if p, ok := gs.listenPorts[network]; ok {
		target.Port = p
	} else {
		defPort := transport.DefaultPort(network)
		target.Port = &defPort
	}
	return &target
}

func (gs *SipStack) RememberInviteRequest(request sip.Request) {
	if key, err := transaction.MakeClientTxKey(request); err == nil {
		gs.invitesLock.Lock()
		gs.invites[key] = request
		gs.invitesLock.Unlock()

		time.AfterFunc(time.Minute, func() {
			gs.invitesLock.Lock()
			delete(gs.invites, key)
			gs.invitesLock.Unlock()
		})
	} else {
		gs.Log().WithFields(map[string]interface{}{
			"sip_request": request.Short(),
		}).Errorf("remember of the request failed: %s", err)
	}
}

func (gs *SipStack) AckInviteRequest(request sip.Request, response sip.Response) {
	ackRequest := sip.NewAckRequest("", request, response, log.Fields{
		"sent_at": time.Now(),
	})
	ackRequest.SetSource(request.Source())
	ackRequest.SetDestination(request.Destination())
	if err := gs.Send(ackRequest); err != nil {
		gs.Log().WithFields(map[string]interface{}{
			"invite_request":  request.Short(),
			"invite_response": response.Short(),
			"ack_request":     ackRequest.Short(),
		}).Errorf("send ACK request failed: %s", err)
	}
}

func (gs *SipStack) CancelRequest(request sip.Request, response sip.Response) {
	cancelRequest := sip.NewCancelRequest("", request, log.Fields{
		"sent_at": time.Now(),
	})
	if err := gs.Send(cancelRequest); err != nil {
		gs.Log().WithFields(map[string]interface{}{
			"invite_request":  request.Short(),
			"invite_response": response.Short(),
			"cancel_request":  cancelRequest.Short(),
		}).Errorf("send CANCEL request failed: %s", err)
	}
}

func (gs *SipStack) prepareRequest(req sip.Request) sip.Request {
	if viaHop, ok := req.ViaHop(); ok {
		if viaHop.Params == nil {
			viaHop.Params = sip.NewParams()
		}
		if !viaHop.Params.Has("branch") {
			viaHop.Params.Add("branch", sip.String{Str: sip.GenerateBranch()})
		}
	} else {
		viaHop = &sip.ViaHop{
			ProtocolName:    "SIP",
			ProtocolVersion: "2.0",
			Params: sip.NewParams().
				Add("branch", sip.String{Str: sip.GenerateBranch()}),
		}

		req.PrependHeaderAfter(sip.ViaHeader{
			viaHop,
		}, "Route")
	}

	gs.appendAutoHeaders(req)

	return req
}

// Respond .
func (gs *SipStack) Respond(res sip.Response) (sip.ServerTransaction, error) {
	if gs.shuttingDown() {
		return nil, fmt.Errorf("can not send through stopped server")
	}

	return gs.tx.Respond(gs.prepareResponse(res))
}

// RespondOnRequest .
func (gs *SipStack) RespondOnRequest(
	request sip.Request,
	status sip.StatusCode,
	reason, body string,
	headers []sip.Header,
) (sip.ServerTransaction, error) {
	response := sip.NewResponseFromRequest("", request, status, reason, body)
	for _, header := range headers {
		response.AppendHeader(header)
	}

	tx, err := gs.Respond(response)
	if err != nil {
		return nil, fmt.Errorf("respond '%d %s' failed: %w", response.StatusCode(), response.Reason(), err)
	}

	return tx, nil
}

// Send .
func (gs *SipStack) Send(msg sip.Message) error {
	if gs.shuttingDown() {
		return fmt.Errorf("can not send through stopped server")
	}

	switch m := msg.(type) {
	case sip.Request:
		msg = gs.prepareRequest(m)
	case sip.Response:
		msg = gs.prepareResponse(m)
	}

	return gs.tp.Send(msg)
}

func (gs *SipStack) prepareResponse(res sip.Response) sip.Response {
	gs.appendAutoHeaders(res)

	return res
}

func (gs *SipStack) shuttingDown() bool {
	return atomic.LoadInt32(&gs.inShutdown) != 0
}

// Shutdown gracefully shutdowns SIP server
func (gs *SipStack) Shutdown() {
	if gs.shuttingDown() {
		return
	}

	atomic.AddInt32(&gs.inShutdown, 1)
	defer atomic.AddInt32(&gs.inShutdown, -1)
	// stop transaction layer
	gs.tx.Cancel()
	<-gs.tx.Done()
	// stop transport layer
	gs.tp.Cancel()
	<-gs.tp.Done()
	// wait for handlers
	gs.hwg.Wait()
}

// OnRequest registers new request callback
func (gs *SipStack) OnRequest(method sip.RequestMethod, handler RequestHandler) error {
	gs.hmu.Lock()
	gs.requestHandlers[method] = handler
	gs.hmu.Unlock()

	return nil
}

func (gs *SipStack) appendAutoHeaders(msg sip.Message) {
	autoAppendMethods := map[sip.RequestMethod]bool{
		sip.INVITE:   true,
		sip.REGISTER: true,
		sip.OPTIONS:  true,
		sip.REFER:    true,
		sip.NOTIFY:   true,
	}

	var msgMethod sip.RequestMethod
	switch m := msg.(type) {
	case sip.Request:
		msgMethod = m.Method()
	case sip.Response:
		if cseq, ok := m.CSeq(); ok && !m.IsProvisional() {
			msgMethod = cseq.MethodName
		}
	}
	if len(msgMethod) > 0 {
		if _, ok := autoAppendMethods[msgMethod]; ok {
			hdrs := msg.GetHeaders("Allow")
			if len(hdrs) == 0 {
				allow := make(sip.AllowHeader, 0)
				for _, method := range gs.getAllowedMethods() {
					allow = append(allow, method)
				}

				msg.AppendHeader(allow)
			}

			hdrs = msg.GetHeaders("Supported")
			if len(hdrs) == 0 {
				msg.AppendHeader(&sip.SupportedHeader{
					Options: gs.extensions,
				})
			}
		}
	}

	if hdrs := msg.GetHeaders("User-Agent"); len(hdrs) == 0 {
		userAgent := sip.UserAgentHeader(DefaultUserAgent)
		msg.AppendHeader(&userAgent)
	}
}

func (gs *SipStack) getAllowedMethods() []sip.RequestMethod {
	methods := []sip.RequestMethod{
		sip.INVITE,
		sip.ACK,
		sip.BYE,
		sip.CANCEL,
		sip.INFO,
		sip.OPTIONS,
	}
	added := map[sip.RequestMethod]bool{
		sip.INVITE:  true,
		sip.ACK:     true,
		sip.BYE:     true,
		sip.CANCEL:  true,
		sip.INFO:    true,
		sip.OPTIONS: true,
	}

	gs.hmu.RLock()
	for method := range gs.requestHandlers {
		if _, ok := added[method]; !ok {
			methods = append(methods, method)
		}
	}
	gs.hmu.RUnlock()

	return methods
}
