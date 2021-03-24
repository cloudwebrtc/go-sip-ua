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

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/transaction"
	"github.com/ghettovoice/gosip/transport"
	"github.com/ghettovoice/gosip/util"
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
	listenPorts           map[string]*sip.Port
	tp                    transport.Layer
	tx                    transaction.Layer
	host                  string
	ip                    net.IP
	inShutdown            int32
	hwg                   *sync.WaitGroup
	hmu                   *sync.RWMutex
	requestHandlers       map[sip.RequestMethod]RequestHandler
	handleConnectionError func(err *transport.ConnectionError)
	extensions            []string
	invites               map[transaction.TxKey]sip.Request
	invitesLock           *sync.RWMutex
	authenticator         *ServerAuthManager
	log                   log.Logger
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

	s := &SipStack{
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
		s.authenticator = &config.ServerAuthManager
	}

	s.log = logger.WithFields(log.Fields{
		"sip_server_ptr": fmt.Sprintf("%p", s),
	})

	s.tp = transport.NewLayer(ip, dnsResolver, config.MsgMapper, logger.WithPrefix("transport.Layer"))

	sipTp := &sipTransport{
		tpl: s.tp,
		s:   s,
	}
	s.tx = transaction.NewLayer(sipTp, logger.WithPrefix("transaction.Layer"))
	go s.serve()

	return s
}

// Log .
func (s *SipStack) Log() log.Logger {
	return s.log
}

// ListenTLS starts serving listeners on the provided address
func (s *SipStack) ListenTLS(protocol string, listenAddr string, options *transport.TLSConfig) error {
	var err error
	network := strings.ToUpper(protocol)
	if options != nil {
		err = s.tp.Listen(network, listenAddr, options)
	} else {
		err = s.tp.Listen(network, listenAddr)
	}
	if err == nil {
		target, err := transport.NewTargetFromAddr(listenAddr)
		if err != nil {
			return err
		}
		target = transport.FillTargetHostAndPort(network, target)
		if _, ok := s.listenPorts[network]; !ok {
			s.listenPorts[network] = target.Port
		}
	}
	return err
}

func (s *SipStack) Listen(protocol string, listenAddr string) error {
	return s.ListenTLS(protocol, listenAddr, nil)
}

func (s *SipStack) serve() {
	defer s.Shutdown()

	for {
		select {
		case tx, ok := <-s.tx.Requests():
			if !ok {
				return
			}
			s.hwg.Add(1)
			go s.handleRequest(tx.Origin(), tx)
		case ack, ok := <-s.tx.Acks():
			if !ok {
				return
			}
			s.hwg.Add(1)
			go s.handleRequest(ack, nil)
		case response, ok := <-s.tx.Responses():
			if !ok {
				return
			}
			logger := s.Log().WithFields(map[string]interface{}{
				"sip_response": response.Short(),
			})
			logger.Warn("received not matched response")
			if key, err := transaction.MakeClientTxKey(response); err == nil {
				s.invitesLock.RLock()
				inviteRequest, ok := s.invites[key]
				s.invitesLock.RUnlock()
				if ok {
					go s.AckInviteRequest(inviteRequest, response)
				}
			}
		case err, ok := <-s.tx.Errors():
			if !ok {
				return
			}
			s.Log().Errorf("received SIP transaction error: %s", err)
		case err, ok := <-s.tp.Errors():
			if !ok {
				return
			}

			s.Log().Errorf("received SIP transport error: %s", err)

			if connError, ok := err.(*transport.ConnectionError); ok {
				if s.handleConnectionError != nil {
					s.handleConnectionError(connError)
				}
			}
		}
	}
}

func (s *SipStack) handleRequest(req sip.Request, tx sip.ServerTransaction) {
	defer s.hwg.Done()

	logger := s.Log().WithFields(req.Fields())
	logger.Debugf("routing incoming SIP request...")

	s.hmu.RLock()
	handler, ok := s.requestHandlers[req.Method()]
	s.hmu.RUnlock()

	if !ok {
		logger.Warnf("SIP request %v handler not found", req.Method())

		res := sip.NewResponseFromRequest("", req, 405, "Method Not Allowed", "")
		if _, err := s.Respond(res); err != nil {
			logger.Errorf("respond '405 Method Not Allowed' failed: %s", err)
		}

		return
	}

	if s.authenticator != nil {
		authenticator := s.authenticator.Authenticator
		requiresChallenge := s.authenticator.RequiresChallenge
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
func (s *SipStack) Request(req sip.Request) (sip.ClientTransaction, error) {
	if s.shuttingDown() {
		return nil, fmt.Errorf("can not send through stopped server")
	}

	return s.tx.Request(s.prepareRequest(req))
}

func (s SipStack) GetNetworkInfo(protocol string) *transport.Target {
	logger := s.Log()

	var target transport.Target
	if v, err := util.ResolveSelfIP(); err == nil {
		target.Host = v.String()
	} else {
		logger.Panicf("resolve host IP failed: %s", err)
	}

	network := strings.ToUpper(protocol)
	if p, ok := s.listenPorts[network]; ok {
		target.Port = p
	} else {
		defPort := sip.DefaultPort(network)
		target.Port = &defPort
	}
	return &target
}

func (s *SipStack) RememberInviteRequest(request sip.Request) {
	if key, err := transaction.MakeClientTxKey(request); err == nil {
		s.invitesLock.Lock()
		s.invites[key] = request
		s.invitesLock.Unlock()

		time.AfterFunc(time.Minute, func() {
			s.invitesLock.Lock()
			delete(s.invites, key)
			s.invitesLock.Unlock()
		})
	} else {
		s.Log().WithFields(map[string]interface{}{
			"sip_request": request.Short(),
		}).Errorf("remember of the request failed: %s", err)
	}
}

func (s *SipStack) AckInviteRequest(request sip.Request, response sip.Response) {
	ackRequest := sip.NewAckRequest("", request, response, "", log.Fields{
		"sent_at": time.Now(),
	})
	ackRequest.SetSource(request.Source())
	ackRequest.SetDestination(request.Destination())
	if err := s.Send(ackRequest); err != nil {
		s.Log().WithFields(map[string]interface{}{
			"invite_request":  request.Short(),
			"invite_response": response.Short(),
			"ack_request":     ackRequest.Short(),
		}).Errorf("send ACK request failed: %s", err)
	}
}

func (s *SipStack) CancelRequest(request sip.Request, response sip.Response) {
	cancelRequest := sip.NewCancelRequest("", request, log.Fields{
		"sent_at": time.Now(),
	})
	if err := s.Send(cancelRequest); err != nil {
		s.Log().WithFields(map[string]interface{}{
			"invite_request":  request.Short(),
			"invite_response": response.Short(),
			"cancel_request":  cancelRequest.Short(),
		}).Errorf("send CANCEL request failed: %s", err)
	}
}

func (s *SipStack) prepareRequest(req sip.Request) sip.Request {
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

	s.appendAutoHeaders(req)

	return req
}

// Respond .
func (s *SipStack) Respond(res sip.Response) (sip.ServerTransaction, error) {
	if s.shuttingDown() {
		return nil, fmt.Errorf("can not send through stopped server")
	}

	return s.tx.Respond(s.prepareResponse(res))
}

// RespondOnRequest .
func (s *SipStack) RespondOnRequest(
	request sip.Request,
	status sip.StatusCode,
	reason, body string,
	headers []sip.Header,
) (sip.ServerTransaction, error) {
	response := sip.NewResponseFromRequest("", request, status, reason, body)
	for _, header := range headers {
		response.AppendHeader(header)
	}

	tx, err := s.Respond(response)
	if err != nil {
		return nil, fmt.Errorf("respond '%d %s' failed: %w", response.StatusCode(), response.Reason(), err)
	}

	return tx, nil
}

// Send .
func (s *SipStack) Send(msg sip.Message) error {
	if s.shuttingDown() {
		return fmt.Errorf("can not send through stopped server")
	}

	switch m := msg.(type) {
	case sip.Request:
		msg = s.prepareRequest(m)
	case sip.Response:
		msg = s.prepareResponse(m)
	}

	return s.tp.Send(msg)
}

func (s *SipStack) prepareResponse(res sip.Response) sip.Response {
	s.appendAutoHeaders(res)
	return res
}

func (s *SipStack) shuttingDown() bool {
	return atomic.LoadInt32(&s.inShutdown) != 0
}

// Shutdown gracefully shutdowns SIP server
func (s *SipStack) Shutdown() {
	if s.shuttingDown() {
		return
	}

	atomic.AddInt32(&s.inShutdown, 1)
	defer atomic.AddInt32(&s.inShutdown, -1)
	// stop transaction layer
	s.tx.Cancel()
	<-s.tx.Done()
	// stop transport layer
	s.tp.Cancel()
	<-s.tp.Done()
	// wait for handlers
	s.hwg.Wait()
}

// OnRequest registers new request callback
func (s *SipStack) OnRequest(method sip.RequestMethod, handler RequestHandler) error {
	s.hmu.Lock()
	s.requestHandlers[method] = handler
	s.hmu.Unlock()

	return nil
}

func (s *SipStack) OnConnectionError(handler func(err *transport.ConnectionError)) {
	s.hmu.Lock()
	s.handleConnectionError = handler
	s.hmu.Unlock()
}

func (s *SipStack) appendAutoHeaders(msg sip.Message) {
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
				for _, method := range s.getAllowedMethods() {
					allow = append(allow, method)
				}

				msg.AppendHeader(allow)
			}

			hdrs = msg.GetHeaders("Supported")
			if len(hdrs) == 0 {
				msg.AppendHeader(&sip.SupportedHeader{
					Options: s.extensions,
				})
			}
		}
	}

	if hdrs := msg.GetHeaders("User-Agent"); len(hdrs) == 0 {
		userAgent := sip.UserAgentHeader(DefaultUserAgent)
		msg.AppendHeader(&userAgent)
	}

	if s.tp.IsStreamed(msg.Transport()) {
		if hdrs := msg.GetHeaders("Content-Length"); len(hdrs) == 0 {
			msg.SetBody(msg.Body(), true)
		}
	}
}

func (s *SipStack) getAllowedMethods() []sip.RequestMethod {
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

	s.hmu.RLock()
	for method := range s.requestHandlers {
		if _, ok := added[method]; !ok {
			methods = append(methods, method)
		}
	}
	s.hmu.RUnlock()

	return methods
}

type sipTransport struct {
	tpl transport.Layer
	s   *SipStack
}

func (tp *sipTransport) Messages() <-chan sip.Message {
	return tp.tpl.Messages()
}

func (tp *sipTransport) Send(msg sip.Message) error {
	return tp.s.Send(msg)
}

func (tp *sipTransport) IsReliable(network string) bool {
	return tp.tpl.IsReliable(network)
}

func (tp *sipTransport) IsStreamed(network string) bool {
	return tp.tpl.IsStreamed(network)
}
