package session

import (
	"context"
	"fmt"
	"sync"

	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/util"
)

type RequestCallback func(ctx context.Context, request sip.Request, authorizer sip.Authorizer, waitForResult bool, attempt int) (sip.Response, error)

type Session struct {
	lock           sync.RWMutex
	requestCallbck RequestCallback
	status         Status
	callID         sip.CallID
	offer          string
	answer         string
	request        sip.Request
	response       sip.Response
	transaction    sip.Transaction
	direction      Direction
	uaType         string // UAS | UAC
	contact        *sip.ContactHeader
	localURI       sip.Address
	remoteURI      sip.Address
	remoteTarget   sip.Uri
	routeSet       []sip.Uri
	logger         log.Logger
}

func NewInviteSession(reqcb RequestCallback, uaType string,
	contact *sip.ContactHeader, req sip.Request, cid sip.CallID,
	tx sip.Transaction, dir Direction, logger log.Logger) *Session {
	s := &Session{
		requestCallbck: reqcb,
		uaType:         uaType,
		callID:         cid,
		transaction:    tx,
		direction:      dir,
		offer:          "",
		answer:         "",
		contact:        contact,
	}

	s.logger = utils.NewLogrusLogger(log.DebugLevel, "Session", nil)

	to, _ := req.To()
	from, _ := req.From()

	if to.Params != nil && !to.Params.Has("tag") {
		to.Params.Add("tag", sip.String{Str: util.RandString(8)})
		req.RemoveHeader("To")
		req.AppendHeader(to)
	}

	if uaType == "UAS" {
		s.localURI = sip.Address{Uri: to.Address, Params: to.Params}
		s.remoteURI = sip.Address{Uri: from.Address, Params: from.Params}
		s.remoteTarget = contact.Address
		s.offer = req.Body()
		s.StoreRouteSet(req, false)
	} else if uaType == "UAC" {
		s.localURI = sip.Address{Uri: from.Address, Params: from.Params}
		s.remoteURI = sip.Address{Uri: to.Address, Params: to.Params}
		s.remoteTarget = req.Recipient()
		s.offer = req.Body()
	}

	s.request = req
	return s
}

func (s *Session) Log() log.Logger {
	return s.logger
}

func (s *Session) String() string {
	return "Local: " + s.localURI.String() + ", Remote: " + s.remoteURI.String()
}

func (s *Session) LocalURI() sip.Address {
	return s.localURI
}

func (s *Session) RemoteURI() sip.Address {
	return s.remoteURI
}

func (s *Session) LocalSdp() string {
	if s.uaType == "UAC" {
		return s.offer
	}
	return s.answer
}

func (s *Session) RemoteSdp() string {
	if s.uaType == "UAS" {
		return s.offer
	}
	return s.answer
}

func (s *Session) Contact() string {
	return s.contact.String()
}

func (s *Session) CallID() *sip.CallID {
	return &s.callID
}

func (s *Session) Request() sip.Request {
	return s.request
}

func (s *Session) Response() sip.Response {
	return s.response
}

func (s *Session) IsInProgress() bool {
	switch s.status {
	case InviteSent:
		fallthrough
	case Provisional:
		fallthrough
	case EarlyMedia:
		fallthrough
	case InviteReceived:
		fallthrough
	case WaitingForAnswer:
		return true
	default:
		return false
	}
}

func (s *Session) IsEstablished() bool {
	switch s.status {
	case Answered:
		fallthrough
	case WaitingForACK:
		fallthrough
	case Confirmed:
		return true
	default:
		return false
	}
}

func (s *Session) IsEnded() bool {
	switch s.status {
	case Failure:
		fallthrough
	case Canceled:
		fallthrough
	case TimedOut:
		fallthrough
	case Terminated:
		return true
	default:
		return false
	}
}

func (s *Session) StoreRouteSet(msg sip.Message, reverse bool) {
	if hdrs := msg.GetHeaders("Record-Route"); len(hdrs) > 0 {
		s.Log().Debug("Storing Route-Set")
		l := 0
		for _, rr := range hdrs {
			l += len(rr.(*sip.RecordRouteHeader).Addresses)
		}
		rs := make([]sip.Uri, l)
		i := 0
		if reverse {
			i = l-1
		}
		for _, rr := range hdrs {
			for _, r := range rr.(*sip.RecordRouteHeader).Addresses {
				rs[i] = r
				if reverse {
					i -= 1
				} else {
					i += 1
				}
			}
		}
		s.routeSet = rs
	}
}

func (s *Session) StoreRequest(request sip.Request) {
	s.request = request
}

func (s *Session) StoreResponse(response sip.Response) {
	if s.uaType == "UAC" {
		to, _ := response.To()
		if to.Params != nil && to.Params.Has("tag") {
			//Update to URI.
			s.remoteURI = sip.Address{Uri: to.Address, Params: to.Params}
			if ct, ok:= response.Contact(); ok {
				s.remoteTarget = ct.Address
			}
			if response.IsSuccess() || response.IsProvisional() {
				if s.Status() != Confirmed && (response.Method() == sip.INVITE || response.Method() == sip.SUBSCRIBE) {
					s.routeSet = nil
					s.StoreRouteSet(response, true)
				}
			}
		}

		sdp := response.Body()
		if len(sdp) > 0 {
			s.answer = sdp
		}
	}
	s.response = response
}

func (s *Session) StoreTransaction(tx sip.Transaction) {
	if s.transaction != nil {
		s.transaction.Done()
	}
	s.transaction = tx
}

func (s *Session) SetState(status Status) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.status = status
}

func (s *Session) Status() Status {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.status
}

func (s *Session) Direction() Direction {
	return s.direction
}

// GetEarlyMedia Get sdp for early media.
func (s *Session) GetEarlyMedia() string {
	return s.answer
}

//ProvideOffer .
func (s *Session) ProvideOffer(sdp string) {
	s.offer = sdp
}

// ProvideAnswer .
func (s *Session) ProvideAnswer(sdp string) {
	s.answer = sdp
}

//Info send SIP INFO
func (s *Session) Info(content string, contentType string) {
	method := sip.INFO
	req := s.makeRequest(s.uaType, method, sip.MessageID(s.callID), s.request, s.response)
	req.SetBody(content, true)
	hdr := sip.ContentType(contentType)
	req.AppendHeader(&hdr)
	s.sendRequest(req)
}

//ReInvite send re-INVITE
func (s *Session) ReInvite() {
	method := sip.INVITE
	req := s.makeRequest(s.uaType, method, sip.MessageID(s.callID), s.request, s.response)
	req.SetBody(s.offer, true)
	hdr := sip.ContentType("application/sdp")
	req.AppendHeader(&hdr)
	s.sendRequest(req)
}

//Bye send Bye request.
func (s *Session) Bye() (sip.Response, error) {
	req := s.makeRequest(s.uaType, sip.BYE, sip.MessageID(s.callID), s.request, s.response)
	resp, err := s.sendRequest(req)
	if err == nil {
		s.SetState(Terminated)
	}
	return resp, err
}

func (s *Session) sendRequest(req sip.Request) (sip.Response, error) {
	s.Log().Debugf(s.uaType+" send request: %v => \n%v", req.Method(), req)
	return s.requestCallbck(context.TODO(), req, nil, false, 1)
}

// Reject Reject incoming call or for re-INVITE or UPDATE,
func (s *Session) Reject(statusCode sip.StatusCode, reason string) {
	tx := (s.transaction.(sip.ServerTransaction))
	request := s.request
	s.Log().Debugf("Reject: Request => %s, body => %s", request.Short(), request.Body())
	response := sip.NewResponseFromRequest(request.MessageID(), request, statusCode, reason, "")
	response.AppendHeader(s.contact)
	tx.Respond(response)
}

//End end session
func (s *Session) End() error {
	switch s.status {
	// - UAC -
	case InviteSent:
		fallthrough
	case Provisional:
		fallthrough
	case EarlyMedia:
		s.Log().Info("Canceling session.")
		switch s.transaction.(type) {
		case sip.ClientTransaction:
			s.transaction.(sip.ClientTransaction).Cancel()
		case sip.ServerTransaction:
			s.transaction.(sip.ServerTransaction).Done()
		}

	// - UAS -
	case InviteReceived:
		fallthrough
	case WaitingForAnswer:
		fallthrough
	case Answered:
		s.Log().Info("Rejecting session")
		s.Reject(603, "Decline")

	case WaitingForACK:
		fallthrough
	case Confirmed:
		s.Log().Info("Terminating session.")
		s.Bye()

	case Terminated:
		s.Log().Info("Session already terminated")

	default:
		err := fmt.Errorf("invalid status: %v", s.status)
		s.Log().Errorf("Session::End() %v", err)
		return err
	}


	return nil
}

// Accept 200
func (s *Session) Accept(statusCode sip.StatusCode) {
	tx := (s.transaction.(sip.ServerTransaction))

	if len(s.answer) == 0 {
		s.Log().Errorf("Answer sdp is nil!")
		return
	}
	request := s.request
	response := sip.NewResponseFromRequest(request.MessageID(), request, statusCode, "OK", s.answer)

	hdrs := request.GetHeaders("Content-Type")
	if len(hdrs) == 0 {
		contentType := sip.ContentType("application/sdp")
		response.AppendHeader(&contentType)
	} else {
		sip.CopyHeaders("Content-Type", request, response)
	}

	response.AppendHeader(s.contact)
	response.SetBody(s.answer, true)

	s.response = response
	tx.Respond(response)

	s.SetState(WaitingForACK)
}

// Redirect send a 3xx
func (s *Session) Redirect(target string, code sip.StatusCode) {

}

// Provisional send a provisional code 100|180|183
func (s *Session) Provisional(statusCode sip.StatusCode, reason string) {
	tx := (s.transaction.(sip.ServerTransaction))
	request := s.request
	response := sip.NewResponseFromRequest(request.MessageID(), request, statusCode, reason, s.answer)
	if len(s.answer) > 0 {
		hdrs := response.GetHeaders("Content-Type")
		if len(hdrs) == 0 {
			contentType := sip.ContentType("application/sdp")
			response.AppendHeader(&contentType)
		} else {
			sip.CopyHeaders("Content-Type", request, response)
		}
		response.SetBody(s.answer, true)
	}
	if statusCode == 100 {
		response.GetHeaders("To")[0].(*sip.ToHeader).Params.Remove("tag")
	}
	response.AppendHeader(s.contact)

	s.response = response
	tx.Respond(response)
}

func (s *Session) makeRequest(uaType string, method sip.RequestMethod, msgID sip.MessageID, inviteRequest sip.Request, inviteResponse sip.Response) sip.Request {
	newRequest := sip.NewRequest(
		msgID,
		method,
		s.remoteTarget,
		inviteRequest.SipVersion(),
		[]sip.Header{},
		"",
		inviteRequest.Fields().
			WithFields(log.Fields{
				"invite_request_id": inviteRequest.MessageID(),
			}),
	)

	from := s.localURI.Clone().AsFromHeader()
	newRequest.AppendHeader(from)
	to := s.remoteURI.Clone().AsToHeader()
	newRequest.AppendHeader(to)
	newRequest.SetRecipient(s.request.Recipient())
	sip.CopyHeaders("Via", inviteRequest, newRequest)
	newRequest.AppendHeader(s.contact)
	if len(s.routeSet) > 0 {
		newRequest.AppendHeader(&sip.RouteHeader{Addresses: s.routeSet})
	}

	maxForwardsHeader := sip.MaxForwards(70)
	newRequest.AppendHeader(&maxForwardsHeader)
	sip.CopyHeaders("Call-ID", inviteRequest, newRequest)
	sip.CopyHeaders("CSeq", inviteRequest, newRequest)

	cseq, _ := newRequest.CSeq()
	cseq.SeqNo++
	cseq.MethodName = method

	return newRequest
}
