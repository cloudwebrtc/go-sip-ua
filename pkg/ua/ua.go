package ua

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/auth"
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/transaction"
	"github.com/ghettovoice/gosip/util"

	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
)

// SessionKey - Session Key for Session Storage
type SessionKey struct {
	CallID  sip.CallID
	FromTag sip.MaybeString
	ToTag   sip.MaybeString
}

// NewSessionKey - Build a Session Key quickly
func NewSessionKey(callID sip.CallID, fromTag, toTag sip.MaybeString) SessionKey {
	return SessionKey{
		CallID:  callID,
		FromTag: fromTag,
		ToTag:   toTag,
	}
}

// UserAgentConfig .
type UserAgentConfig struct {
	SipStack *stack.SipStack
	Logger   log.Logger
}

// InviteSessionHandler .
type InviteSessionHandler func(s *session.Session, req *sip.Request, resp *sip.Response, status session.Status)

// RegisterHandler .
type RegisterHandler func(regState account.RegisterState)

// UserAgent .
type UserAgent struct {
	InviteStateHandler   InviteSessionHandler
	RegisterStateHandler RegisterHandler
	config               *UserAgentConfig
	iss                  sync.Map /*Invite Session*/
	log                  log.Logger
}

// NewUserAgent .
func NewUserAgent(config *UserAgentConfig) *UserAgent {
	ua := &UserAgent{
		config:               config,
		iss:                  sync.Map{},
		InviteStateHandler:   nil,
		RegisterStateHandler: nil,
		log:                  config.Logger.WithPrefix("user_agent"),
	}
	stack := config.SipStack
	stack.OnRequest(sip.INVITE, ua.handleInvite)
	stack.OnRequest(sip.ACK, ua.handleACK)
	stack.OnRequest(sip.BYE, ua.handleBye)
	stack.OnRequest(sip.CANCEL, ua.handleCancel)
	stack.OnRequest(sip.UPDATE, ua.handleUpdate)
	stack.OnRequest(sip.OPTIONS, ua.handleOptions)
	return ua
}

func (ua *UserAgent) Log() log.Logger {
	return ua.log
}

func (ua *UserAgent) GetInviteSessionsCount() int {
	length := 0
	ua.iss.Range(func(key, value any) bool {
		length++

		return true
	})

	return length
}

func (ua *UserAgent) handleInviteState(is *session.Session, request *sip.Request, response *sip.Response, state session.Status, tx *sip.Transaction) {
	if request != nil && *request != nil {
		is.StoreRequest(*request)
	}

	if response != nil && *response != nil {
		is.StoreResponse(*response)
	}

	if tx != nil {
		is.StoreTransaction(*tx)
	}

	is.SetState(state)

	if ua.InviteStateHandler != nil {
		ua.InviteStateHandler(is, request, response, state)
	}
}

func (ua *UserAgent) buildRequest(
	method sip.RequestMethod,
	from *sip.Address,
	to *sip.Address,
	contact *sip.Address,
	recipient sip.SipUri,
	routes []sip.Uri,
	callID *sip.CallID,
	customHeaders []sip.Header) (*sip.Request, error) {

	builder := sip.NewRequestBuilder()
	builder.AddVia(&sip.ViaHop{
		ProtocolName:    "SIP",
		ProtocolVersion: "2.0",
		Transport:       "UDP",
		Host:            from.Uri.Host(),
		Port:            nil,
		Params:          sip.NewParams().Add("rport", nil),
	})

	for _, header := range customHeaders {
		builder.AddHeader(header)
	}

	builder.SetMethod(method)
	builder.SetFrom(from)
	builder.SetTo(to)
	builder.SetContact(contact)
	builder.SetRecipient(recipient.Clone())

	if len(routes) > 0 {
		builder.SetRoutes(routes)
	}

	if callID != nil {
		builder.SetCallID(callID)
	}

	req, err := builder.Build()
	if err != nil {
		ua.Log().Errorf("err => %v", err)
		return nil, err
	}

	//ua.Log().Infof("buildRequest %s => \n%v", method, req)
	return &req, nil
}

func (ua *UserAgent) SendRegister(profile *account.Profile, recipient sip.SipUri, expires uint32, userdata interface{}) (*Register, error) {
	register := NewRegister(ua, profile, recipient, userdata)
	err := register.SendRegister(expires)
	if err != nil {
		ua.Log().Errorf("SendRegister failed, err => %v", err)
		return nil, err
	}
	return register, nil
}

func (ua *UserAgent) Invite(profile *account.Profile, target sip.Uri, recipient sip.SipUri, body *string, callID *sip.CallID, headers []sip.Header) (*session.Session, error) {
	return ua.InviteWithContext(context.TODO(), profile, target, recipient, body, callID, headers)
}

func (ua *UserAgent) InviteWithContext(ctx context.Context, profile *account.Profile, target sip.Uri, recipient sip.SipUri, body *string, callID *sip.CallID, headers []sip.Header) (*session.Session, error) {
	from := &sip.Address{
		DisplayName: sip.String{Str: profile.DisplayName},
		Uri:         profile.URI,
		Params:      sip.NewParams().Add("tag", sip.String{Str: util.RandString(8)}),
	}

	contact := profile.Contact()

	to := &sip.Address{
		Uri: target,
	}

	request, err := ua.buildRequest(sip.INVITE, from, to, contact, recipient, profile.Routes, callID, headers)
	if err != nil {
		ua.Log().Errorf("INVITE: err = %v", err)
		return nil, err
	}

	if body != nil {
		(*request).SetBody(*body, true)
		contentType := sip.ContentType("application/sdp")
		(*request).AppendHeader(&contentType)
	}

	var authorizer *auth.ClientAuthorizer = nil
	if profile.AuthInfo != nil {
		authorizer = auth.NewClientAuthorizer(profile.AuthInfo.AuthUser, profile.AuthInfo.Password)
	}

	resp, err := ua.RequestWithContext(ctx, *request, authorizer, false, 1)
	if err != nil {
		ua.Log().Errorf("INVITE: Request [INVITE] failed, err => %v", err)
		return nil, err
	}

	if resp != nil {
		stateCode := resp.StatusCode()
		ua.Log().Debugf("INVITE: resp %d => %s", stateCode, resp.String())
		return nil, fmt.Errorf("Invite session is unsuccessful, code: %d, reason: %s", stateCode, resp.String())
	}

	callID, ok := (*request).CallID()
	if ok {
		fromTag := utils.GetFromTag(*request)
		toTag := utils.GetToTag(*request)
		if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); found {
			return v.(*session.Session), nil
		}
	}

	return nil, fmt.Errorf("invite session not found, unknown errors")
}

func (ua *UserAgent) Request(req *sip.Request) (sip.ClientTransaction, error) {
	return ua.config.SipStack.Request(*req)
}

func (ua *UserAgent) handleBye(request sip.Request, tx sip.ServerTransaction) {
	ua.Log().Debugf("handleBye: Request => %s, body => %s", request.Short(), request.Body())
	response := sip.NewResponseFromRequest(request.MessageID(), request, 200, "OK", "")

	if viaHop, ok := request.ViaHop(); ok {
		var (
			host string
			port sip.Port
		)
		host = viaHop.Host
		if viaHop.Params != nil {
			if received, ok := viaHop.Params.Get("received"); ok && received.String() != "" {
				host = received.String()
			}
			if viaHop.Port != nil {
				port = *viaHop.Port
			} else if rport, ok := viaHop.Params.Get("rport"); ok && rport != nil && rport.String() != "" {
				if p, err := strconv.Atoi(rport.String()); err == nil {
					port = sip.Port(uint16(p))
				}
			} else {
				port = sip.DefaultPort(request.Transport())
			}
		}

		dest := fmt.Sprintf("%v:%v", host, port)
		response.SetDestination(dest)
	}

	tx.Respond(response)
	callID, ok := request.CallID()
	if ok {
		isUACCase := false

		// UAC case (UAS send BYE).
		// Here fromTag in request is UAS-tag and toTag from request - UAC-tag.
		// Since UAC initialized invite session, in iss it stored with UAC-tag as fromTag and UAS-tag as toTag.
		uasTag := utils.GetFromTag(request)
		uacTag := utils.GetToTag(request)
		if v, found := ua.iss.Load(NewSessionKey(*callID, uacTag, uasTag)); found {
			inviteSession := v.(*session.Session)
			ua.iss.Delete(NewSessionKey(*callID, uacTag, uasTag))
			var transaction sip.Transaction = tx.(sip.Transaction)
			ua.handleInviteState(inviteSession, &request, &response, session.Terminated, &transaction)

			isUACCase = true
		}

		// UAS case (UAC send BYE)
		fromTag := utils.GetFromTag(request)
		toTag := utils.GetToTag(request)
		if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); !isUACCase && found {
			inviteSession := v.(*session.Session)
			ua.iss.Delete(NewSessionKey(*callID, fromTag, toTag))
			var transaction sip.Transaction = tx.(sip.Transaction)
			ua.handleInviteState(inviteSession, &request, &response, session.Terminated, &transaction)
		}
	}
}

func (ua *UserAgent) handleCancel(request sip.Request, tx sip.ServerTransaction) {
	ua.Log().Debugf("handleCancel: Request => %s, body => %s", request.Short(), request.Body())
	response := sip.NewResponseFromRequest(request.MessageID(), request, 200, "OK", "")
	tx.Respond(response)

	callID, ok := request.CallID()
	if ok {
		fromTag := utils.GetFromTag(request)
		toTag := utils.GetToTag(request)
		var inviteSession *session.Session
		var isSessionFound = false

		if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); found {
			inviteSession = v.(*session.Session)
			isSessionFound = true
		} else if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, nil)); found {
			inviteSession = v.(*session.Session)
			isSessionFound = true
			toTag = nil
		}

		if isSessionFound {
			ua.iss.Delete(NewSessionKey(*callID, fromTag, toTag))
			var transaction sip.Transaction = tx.(sip.Transaction)
			inviteSession.SetState(session.Canceled)
			ua.handleInviteState(inviteSession, &request, nil, session.Canceled, &transaction)
		}
	}
}

func (ua *UserAgent) handleACK(request sip.Request, tx sip.ServerTransaction) {
	ua.Log().Debugf("handleACK => %s, body => %s", request.Short(), request.Body())

	callID, ok := request.CallID()
	if ok {
		fromTag := utils.GetFromTag(request)
		toTag := utils.GetToTag(request)
		if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); found {
			// handle Ringing or Processing with sdp
			is := v.(*session.Session)
			is.SetState(session.Confirmed)
			ua.handleInviteState(is, &request, nil, session.Confirmed, nil)
		}
	}
}

func (ua *UserAgent) handleInvite(request sip.Request, tx sip.ServerTransaction) {
	ua.Log().Debugf("handleInvite => %s, body => %s", request.Short(), request.Body())

	callID, ok := request.CallID()
	var localTag sip.MaybeString = nil
	if ok {
		var transaction sip.Transaction = tx.(sip.Transaction)
		fromTag := utils.GetFromTag(request)
		toTag := utils.GetToTag(request)
		v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag))
		if toHdr, ok := request.To(); ok && toHdr.Params.Has("tag") {
			if found {
				localTag = toTag
				is := v.(*session.Session)
				is.SetState(session.ReInviteReceived)
				ua.handleInviteState(is, &request, nil, session.ReInviteReceived, &transaction)
			} else {
				// reinvite for transaction we have no record of; reject it
				response := sip.NewResponseFromRequest(request.MessageID(), request, sip.StatusCode(481), "Call/Transaction does not exist", "")
				tx.Respond(response)
			}
		} else {
			if found {
				// retransmission; reject it
				response := sip.NewResponseFromRequest(request.MessageID(), request, sip.StatusCode(482), "Loop Detected", "")
				tx.Respond(response)
			} else {
				if _, ok := request.From(); !ok {
					response := sip.NewResponseFromRequest(request.MessageID(), request, sip.StatusCode(400), "Bad Request", "")
					tx.Respond(response)
					return
				}

				contactHdr, _ := request.Contact()
				contactAddr := ua.updateContact2UAAddr(request.Transport(), contactHdr.Address)
				contactHdr.Address = contactAddr

				is := session.NewInviteSession(ua.RequestWithContext, "UAS", contactHdr, request, *callID, transaction, session.Incoming, ua.Log())
				if isToTag, ok := is.LocalURI().Params.Get("tag"); ok {
					toTag = isToTag
					localTag = toTag
				}
				ua.iss.Store(NewSessionKey(*callID, fromTag, toTag), is)
				is.SetState(session.InviteReceived)
				ua.handleInviteState(is, &request, nil, session.InviteReceived, &transaction)
				is.SetState(session.WaitingForAnswer)
			}
		}
	}

	go func() {
		cancel := <-tx.Cancels()
		if cancel != nil {
			ua.Log().Debugf("Cancel => %s, body => %s", cancel.Short(), cancel.Body())
			response := sip.NewResponseFromRequest(cancel.MessageID(), cancel, 200, "OK", "")
			if callID, ok := response.CallID(); ok {
				fromTag := utils.GetFromTag(cancel)

				// Since invite session saved with valid fromTag and toTag and CANCEL contains only fromTag, extract toTag from created invite session.
				toTag := localTag

				if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); found {
					ua.iss.Delete(NewSessionKey(*callID, fromTag, toTag))
					is := v.(*session.Session)
					is.SetState(session.Canceled)
					ua.handleInviteState(is, &request, &response, session.Canceled, nil)
				}
			}

			tx.Respond(response)
		}
	}()

	go func() {
		ack := <-tx.Acks()
		if ack != nil {
			ua.Log().Debugf("ack => %v", ack)
		}
	}()
}

func (ua *UserAgent) handleUpdate(request sip.Request, tx sip.ServerTransaction) {
	ua.Log().Debugf("handleUpdate: Request => %s", request.Short())

	response := sip.NewResponseFromRequest(request.MessageID(), request, 200, "OK", "")
	tx.Respond(response)
}

func (ua *UserAgent) handleOptions(request sip.Request, tx sip.ServerTransaction) {
	ua.Log().Debugf("handleOptions => %s, body => %s", request.Short(), request.Body())

	if to, ok := request.To(); ok {
		if to.Params != nil && !to.Params.Has("tag") {
			to.Params.Add("tag", sip.String{Str: util.RandString(8)})
			request.RemoveHeader("To")
			request.AppendHeader(to)
		}
	}

	response := sip.NewResponseFromRequest(request.MessageID(), request, 200, "OK", "")
	tx.Respond(response)
}

// RequestWithContext .
func (ua *UserAgent) RequestWithContext(ctx context.Context, request sip.Request, authorizer sip.Authorizer, waitForResult bool, attempt int) (sip.Response, error) {
	s := ua.config.SipStack
	tx, err := s.Request(request)
	if err != nil {
		return nil, err
	}
	var cts sip.Transaction = tx.(sip.Transaction)

	if request.IsInvite() {
		if callID, ok := request.CallID(); ok {
			fromTag := utils.GetFromTag(request)
			toTag := utils.GetToTag(request)
			if _, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); !found {
				contactHdr, _ := request.Contact()
				contactAddr := ua.updateContact2UAAddr(request.Transport(), contactHdr.Address)
				contactHdr.Address = contactAddr
				is := session.NewInviteSession(ua.RequestWithContext, "UAC", contactHdr, request, *callID, cts, session.Outgoing, ua.Log())
				ua.iss.Store(NewSessionKey(*callID, fromTag, toTag), is)
				is.ProvideOffer(request.Body())
				is.SetState(session.InviteSent)
				ua.handleInviteState(is, &request, nil, session.InviteSent, &cts)
			}
		}
	}

	responses := make(chan sip.Response)
	provisionals := make(chan sip.Response)
	errs := make(chan error)
	go func() {
		var lastResponse sip.Response

		previousResponses := make([]sip.Response, 0)
		previousResponsesStatuses := make(map[sip.StatusCode]bool)

		for {
			select {
			case <-ctx.Done():
				if lastResponse != nil && lastResponse.IsProvisional() {
					s.CancelRequest(request, lastResponse)
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

				switch err.(type) {
				case *transaction.TxTimeoutError:
					{
						errs <- sip.NewRequestError(408, "Request Timeout", request, lastResponse)
						return
					}
				}

				//errs <- err
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
					provisionals <- response
					continue
				}

				// success
				if response.IsSuccess() {
					response.SetPrevious(previousResponses)

					if request.IsInvite() {
						s.AckInviteRequest(request, response)
						s.RememberInviteRequest(request)
						go func() {
							for response := range tx.Responses() {
								s.AckInviteRequest(request, response)
							}
						}()
					}
					responses <- response
					tx.Done()
					return
				}

				// auth request
				needAuth := (response.StatusCode() == 401 || response.StatusCode() == 407) && attempt < 2
				if needAuth && authorizer != nil {

					// Since the first time we send request with local contact URI, we should extract
					// valid (public) host&port from Via response header parameters:
					// host key	= "received"
					// port key = "rport"
					//
					// Also we should update profile.ContactURI.
					if viaHeader, ok := response.Via(); ok {
						if len(viaHeader) > 0 {
							viaHeaderParams := viaHeader[0].Params

							contactHeader, _ := request.Contact()

							if receivedIPAddress, ok := viaHeaderParams.Get("received"); ok && receivedIPAddress != nil {
								contactHeader.Address.SetHost(receivedIPAddress.String())
							}

							if rport, ok := viaHeaderParams.Get("rport"); ok && rport != nil {
								uintRPort, err := strconv.ParseUint(rport.String(), 10, 16)

								// rport parsed successfully.
								if err == nil {
									var port = sip.Port(uint16(uintRPort))
									contactHeader.Address.SetPort(&port)
								}
							}

							request.ReplaceHeaders("Contact", []sip.Header{contactHeader})
						}
					}

					if err := authorizer.AuthorizeRequest(request, response); err != nil {
						errs <- err
						return
					}
					if response, err := ua.RequestWithContext(ctx, request, authorizer, true, attempt+1); err == nil {
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

	waitForResponse := func(cts *sip.Transaction) (sip.Response, error) {
		for {
			select {
			case provisional := <-provisionals:
				callID, ok := provisional.CallID()
				if ok {
					fromTag := utils.GetFromTag(provisional)
					toTag := utils.GetToTag(provisional)
					var inviteSession *session.Session
					var isSessionFound = false

					if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); found {
						inviteSession = v.(*session.Session)
						isSessionFound = true
					} else if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, nil)); found {
						inviteSession = v.(*session.Session)
						isSessionFound = true
						if toTag != nil {
							ua.iss.Delete(NewSessionKey(*callID, fromTag, nil))
							ua.iss.Store(NewSessionKey(*callID, fromTag, toTag), v)
						}
					}

					if isSessionFound {
						inviteSession.StoreResponse(provisional)
						// handle Ringing or Processing with sdp
						ua.handleInviteState(inviteSession, &request, &provisional, session.Provisional, cts)
						if len(provisional.Body()) > 0 {
							inviteSession.SetState(session.EarlyMedia)
							ua.handleInviteState(inviteSession, &request, &provisional, session.EarlyMedia, cts)
						}
					}
				}
			case err := <-errs:
				//TODO: error type switch transaction.TxTimeoutError
				switch err.(type) {
				case *transaction.TxTimeoutError:
					//errs <- sip.NewRequestError(408, "Request Timeout", nil, nil)
					return nil, err
				case *sip.RequestError:
					request := (err.(*sip.RequestError)).Request
					response := (err.(*sip.RequestError)).Response
					callID, ok := request.CallID()
					if ok {
						fromTag := utils.GetFromTag(request)
						toTag := utils.GetToTag(request)
						if response != nil {
							toTag = utils.GetToTag(response)
						}
						var inviteSession *session.Session
						var isSessionFound = false

						if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); found {
							inviteSession = v.(*session.Session)
							isSessionFound = true
						} else if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, nil)); found {
							inviteSession = v.(*session.Session)
							isSessionFound = true
							toTag = nil
						}

						if isSessionFound {
							ua.iss.Delete(NewSessionKey(*callID, fromTag, toTag))
							inviteSession.SetState(session.Failure)
							ua.handleInviteState(inviteSession, &request, &response, session.Failure, nil)
						}
					}
					return nil, err
				default:
				}
				return nil, err
			case response := <-responses:
				callID, ok := response.CallID()
				if ok {
					fromTag := utils.GetFromTag(response)
					toTag := utils.GetToTag(response)
					var inviteSession *session.Session
					var isSessionFound = false

					if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, toTag)); found {
						inviteSession = v.(*session.Session)
						isSessionFound = true
					} else if v, found := ua.iss.Load(NewSessionKey(*callID, fromTag, nil)); found {
						inviteSession = v.(*session.Session)
						isSessionFound = true
						if toTag != nil {
							ua.iss.Delete(NewSessionKey(*callID, fromTag, nil))
							ua.iss.Store(NewSessionKey(*callID, fromTag, toTag), v)
						}
					}

					if isSessionFound {
						if request.IsInvite() {
							inviteSession.SetState(session.Confirmed)
							ua.handleInviteState(inviteSession, &request, &response, session.Confirmed, nil)
						} else if request.Method() == sip.BYE {
							ua.iss.Delete(NewSessionKey(*callID, fromTag, toTag))
							inviteSession.SetState(session.Terminated)
							ua.handleInviteState(inviteSession, &request, &response, session.Terminated, nil)
						}
					}
				}
				return response, nil
			}
		}
	}

	if !waitForResult {
		go waitForResponse(&cts)
		return nil, err
	}
	return waitForResponse(&cts)
}

func (ua *UserAgent) Shutdown() {
	ua.config.SipStack.Shutdown()
}

func (ua *UserAgent) updateContact2UAAddr(transport string, from sip.ContactUri) sip.ContactUri {
	stackAddr := ua.config.SipStack.GetNetworkInfo(transport)
	ret := from.Clone()
	ret.SetHost(stackAddr.Host)
	ret.SetPort(stackAddr.Port)
	return ret
}
