package endpoint

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

// EndPointConfig describes available options
type EndPointConfig struct {
	// Public IP address or domain name, if empty auto resolved IP will be used.
	Host string
	// Dns is an address of the public DNS server to use in SRV lookup.
	Dns               string
	Extensions        []string
	MsgMapper         sip.MessageMapper
	ServerAuthManager ServerAuthManager
}

// EndPoint is a SIP Client/Server
type EndPoint struct {
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

// NewEndPoint creates new instance of SIP server.
func NewEndPoint(config *EndPointConfig, logger log.Logger) *EndPoint {
	if config == nil {
		config = &EndPointConfig{}
	}

	logger = logger.WithPrefix("EndPoint")

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

	e := &EndPoint{
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
		e.authenticator = &config.ServerAuthManager
	}

	e.log = logger.WithFields(log.Fields{
		"sip_server_ptr": fmt.Sprintf("%p", e),
	})
	e.tp = transport.NewLayer(ip, dnsResolver, config.MsgMapper, e.Log())
	e.tx = transaction.NewLayer(e.tp, utils.NewLogrusLogger(logrus.ErrorLevel) /*e.Log().WithFields(e.tp.Log().Fields())*/)

	go e.serve()

	return e
}

// Log .
func (e *EndPoint) Log() log.Logger {
	return e.log
}

// Listen ListenAndServe starts serving listeners on the provided address
func (e *EndPoint) Listen(protocol string, listenAddr string, options *transport.TLSConfig) error {
	network := strings.ToUpper(protocol)
	err := e.tp.Listen(network, listenAddr, options)
	if err == nil {
		target, err := transport.NewTargetFromAddr(listenAddr)
		if err != nil {
			return err
		}
		target = transport.FillTargetHostAndPort(network, target)
		if _, ok := e.listenPorts[network]; !ok {
			e.listenPorts[network] = target.Port
		}
	}
	return err
}

func (e *EndPoint) serve() {
	defer e.Shutdown()

	for {
		select {
		case tx, ok := <-e.tx.Requests():
			if !ok {
				return
			}
			e.hwg.Add(1)
			go e.handleRequest(tx.Origin(), tx)
		case ack, ok := <-e.tx.Acks():
			if !ok {
				return
			}
			e.hwg.Add(1)
			go e.handleRequest(ack, nil)
		case response, ok := <-e.tx.Responses():
			if !ok {
				return
			}
			logger := e.Log().WithFields(map[string]interface{}{
				"sip_response": response.Short(),
			})
			logger.Warn("received not matched response")
			if key, err := transaction.MakeClientTxKey(response); err == nil {
				e.invitesLock.RLock()
				inviteRequest, ok := e.invites[key]
				e.invitesLock.RUnlock()
				if ok {
					go e.AckInviteRequest(inviteRequest, response)
				}
			}
		case err, ok := <-e.tx.Errors():
			if !ok {
				return
			}
			e.Log().Errorf("received SIP transaction error: %s", err)
		case err, ok := <-e.tp.Errors():
			if !ok {
				return
			}

			e.Log().Errorf("received SIP transport error: %s", err)
		}
	}
}

func (e *EndPoint) handleRequest(req sip.Request, tx sip.ServerTransaction) {
	defer e.hwg.Done()

	logger := e.Log().WithFields(req.Fields())
	logger.Info("routing incoming SIP request...")

	e.hmu.RLock()
	handler, ok := e.requestHandlers[req.Method()]
	e.hmu.RUnlock()

	if !ok {
		logger.Warnf("SIP request handler not found")

		res := sip.NewResponseFromRequest("", req, 405, "Method Not Allowed", "")
		if _, err := e.Respond(res); err != nil {
			logger.Errorf("respond '405 Method Not Allowed' failed: %s", err)
		}

		return
	}

	if e.authenticator != nil {
		authenticator := e.authenticator.Authenticator
		requiresChallenge := e.authenticator.RequiresChallenge
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
func (e *EndPoint) Request(req sip.Request) (sip.ClientTransaction, error) {
	if e.shuttingDown() {
		return nil, fmt.Errorf("can not send through stopped server")
	}

	return e.tx.Request(e.prepareRequest(req))
}

// RequestWithContext .
func (e *EndPoint) RequestWithContext(ctx context.Context, request sip.Request, authorizer sip.Authorizer) (sip.Response, error) {
	tx, err := e.Request(request)
	if err != nil {
		return nil, err
	}

	responses := make(chan sip.Response)
	errs := make(chan error)
	go func() {
		var lastResponse sip.Response

		previousResponses := make([]sip.Response, 0)
		previousResponsesStatuses := make(map[sip.StatusCode]bool)

		for {
			select {
			case <-ctx.Done():
				if lastResponse != nil && lastResponse.IsProvisional() {
					e.CancelRequest(request, lastResponse)
				}
				if lastResponse != nil {
					lastResponse.SetPrevious(previousResponses)
				}
				errs <- sip.NewRequestError(487, "Request Terminated", request, lastResponse)
				// pull out later possible transaction responses and errors
				go func() {
					for {
						select {
						case <-tx.Done():
							return
						case <-tx.Errors():
						case <-tx.Responses():
						}
					}
				}()
				return
			case err, ok := <-tx.Errors():
				if !ok {
					if lastResponse != nil {
						lastResponse.SetPrevious(previousResponses)
					}
					errs <- sip.NewRequestError(487, "Request Terminated", request, lastResponse)
					return
				}
				errs <- err
				return
			case response, ok := <-tx.Responses():
				if !ok {
					if lastResponse != nil {
						lastResponse.SetPrevious(previousResponses)
					}
					errs <- sip.NewRequestError(487, "Request Terminated", request, lastResponse)
					return
				}

				response = sip.CopyResponse(response)
				lastResponse = response

				if response.IsProvisional() {
					if _, ok := previousResponsesStatuses[response.StatusCode()]; !ok {
						previousResponses = append(previousResponses, response)
					}
					continue
				}

				// success
				if response.IsSuccess() {
					response.SetPrevious(previousResponses)

					if request.IsInvite() {
						e.AckInviteRequest(request, response)
						e.RememberInviteRequest(request)
						go func() {
							for response := range tx.Responses() {
								e.AckInviteRequest(request, response)
							}
						}()
					}
					responses <- response
					tx.Done()
					return
				}

				// unauth request
				if (response.StatusCode() == 401 || response.StatusCode() == 407) && authorizer != nil {
					if err := authorizer.AuthorizeRequest(request, response); err != nil {
						errs <- err
						return
					}
					if response, err := e.RequestWithContext(ctx, request, nil); err == nil {
						responses <- response
					} else {
						errs <- err
					}
					return
				}

				// failed request
				if lastResponse != nil {
					lastResponse.SetPrevious(previousResponses)
				}
				errs <- sip.NewRequestError(uint(response.StatusCode()), response.Reason(), request, lastResponse)
				return
			}
		}
	}()

	select {
	case err := <-errs:
		return nil, err
	case response := <-responses:
		return response, nil
	}
}

func (e EndPoint) GetNetworkInfo(protocol string) *transport.Target {
	logger := e.Log()

	var target transport.Target
	if v, err := util.ResolveSelfIP(); err == nil {
		target.Host = v.String()
	} else {
		logger.Panicf("resolve host IP failed: %s", err)
	}

	network := strings.ToUpper(protocol)
	if p, ok := e.listenPorts[network]; ok {
		target.Port = p
	} else {
		defPort := transport.DefaultPort(network)
		target.Port = &defPort
	}
	return &target
}

func (e *EndPoint) RememberInviteRequest(request sip.Request) {
	if key, err := transaction.MakeClientTxKey(request); err == nil {
		e.invitesLock.Lock()
		e.invites[key] = request
		e.invitesLock.Unlock()

		time.AfterFunc(time.Minute, func() {
			e.invitesLock.Lock()
			delete(e.invites, key)
			e.invitesLock.Unlock()
		})
	} else {
		e.Log().WithFields(map[string]interface{}{
			"sip_request": request.Short(),
		}).Errorf("remember of the request failed: %s", err)
	}
}

func (e *EndPoint) AckInviteRequest(request sip.Request, response sip.Response) {
	ackRequest := sip.NewAckRequest("", request, response, log.Fields{
		"sent_at": time.Now(),
	})
	ackRequest.SetSource(request.Source())
	ackRequest.SetDestination(request.Destination())
	if err := e.Send(ackRequest); err != nil {
		e.Log().WithFields(map[string]interface{}{
			"invite_request":  request.Short(),
			"invite_response": response.Short(),
			"ack_request":     ackRequest.Short(),
		}).Errorf("send ACK request failed: %s", err)
	}
}

func (e *EndPoint) CancelRequest(request sip.Request, response sip.Response) {
	cancelRequest := sip.NewCancelRequest("", request, log.Fields{
		"sent_at": time.Now(),
	})
	if err := e.Send(cancelRequest); err != nil {
		e.Log().WithFields(map[string]interface{}{
			"invite_request":  request.Short(),
			"invite_response": response.Short(),
			"cancel_request":  cancelRequest.Short(),
		}).Errorf("send CANCEL request failed: %s", err)
	}
}

func (e *EndPoint) prepareRequest(req sip.Request) sip.Request {
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

	e.appendAutoHeaders(req)

	return req
}

// Respond .
func (e *EndPoint) Respond(res sip.Response) (sip.ServerTransaction, error) {
	if e.shuttingDown() {
		return nil, fmt.Errorf("can not send through stopped server")
	}

	return e.tx.Respond(e.prepareResponse(res))
}

// RespondOnRequest .
func (e *EndPoint) RespondOnRequest(
	request sip.Request,
	status sip.StatusCode,
	reason, body string,
	headers []sip.Header,
) (sip.ServerTransaction, error) {
	response := sip.NewResponseFromRequest("", request, status, reason, body)
	for _, header := range headers {
		response.AppendHeader(header)
	}

	tx, err := e.Respond(response)
	if err != nil {
		return nil, fmt.Errorf("respond '%d %s' failed: %w", response.StatusCode(), response.Reason(), err)
	}

	return tx, nil
}

// Send .
func (e *EndPoint) Send(msg sip.Message) error {
	if e.shuttingDown() {
		return fmt.Errorf("can not send through stopped server")
	}

	switch m := msg.(type) {
	case sip.Request:
		msg = e.prepareRequest(m)
	case sip.Response:
		msg = e.prepareResponse(m)
	}

	return e.tp.Send(msg)
}

func (e *EndPoint) prepareResponse(res sip.Response) sip.Response {
	e.appendAutoHeaders(res)

	return res
}

func (e *EndPoint) shuttingDown() bool {
	return atomic.LoadInt32(&e.inShutdown) != 0
}

// Shutdown gracefully shutdowns SIP server
func (e *EndPoint) Shutdown() {
	if e.shuttingDown() {
		return
	}

	atomic.AddInt32(&e.inShutdown, 1)
	defer atomic.AddInt32(&e.inShutdown, -1)
	// stop transaction layer
	e.tx.Cancel()
	<-e.tx.Done()
	// stop transport layer
	e.tp.Cancel()
	<-e.tp.Done()
	// wait for handlers
	e.hwg.Wait()
}

// OnRequest registers new request callback
func (e *EndPoint) OnRequest(method sip.RequestMethod, handler RequestHandler) error {
	e.hmu.Lock()
	e.requestHandlers[method] = handler
	e.hmu.Unlock()

	return nil
}

func (e *EndPoint) appendAutoHeaders(msg sip.Message) {
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
				for _, method := range e.getAllowedMethods() {
					allow = append(allow, method)
				}

				msg.AppendHeader(allow)
			}

			hdrs = msg.GetHeaders("Supported")
			if len(hdrs) == 0 {
				msg.AppendHeader(&sip.SupportedHeader{
					Options: e.extensions,
				})
			}
		}
	}

	if hdrs := msg.GetHeaders("User-Agent"); len(hdrs) == 0 {
		userAgent := sip.UserAgentHeader(DefaultUserAgent)
		msg.AppendHeader(&userAgent)
	}
}

func (e *EndPoint) getAllowedMethods() []sip.RequestMethod {
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

	e.hmu.RLock()
	for method := range e.requestHandlers {
		if _, ok := added[method]; !ok {
			methods = append(methods, method)
		}
	}
	e.hmu.RUnlock()

	return methods
}
