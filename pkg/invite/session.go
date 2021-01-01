package invite

import (
	"context"
	"fmt"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/util"
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewDefaultLogrusLogger().WithPrefix("invite.Session")
}

type Status string

const (
	InviteSent       Status = "InviteSent"       /**< After INVITE s sent */
	InviteReceived   Status = "InviteReceived"   /**< After INVITE s received. */
	ReInviteReceived Status = "ReInviteReceived" /**< After re-INVITE/UPDATE s received */
	//Answer         Status = "Answer"           /**< After response for re-INVITE/UPDATE. */
	Provisional      Status = "Provisional" /**< After response for 1XX. */
	EarlyMedia       Status = "EarlyMedia"  /**< After response 1XX with sdp. */
	WaitingForAnswer Status = "WaitingForAnswer"
	WaitingForACK    Status = "WaitingForACK" /**< After 2xx s sent/received. */
	Answered         Status = "Answered"
	Canceled         Status = "Canceled"
	Confirmed        Status = "Confirmed"  /**< After ACK s sent/received. */
	Failure          Status = "Failure"    /**< Session s rejected or canceled. */
	Terminated       Status = "Terminated" /**< Session s terminated. */
)

type Direction string

const (
	Outgoing Direction = "Outgoing"
	Incoming Direction = "Incoming"
)

type InviteSessionHandler func(s *Session, req *sip.Request, resp *sip.Response, status Status)

type RequestCallback func(ctx context.Context, request sip.Request, authorizer sip.Authorizer) (sip.Response, error)

type Session struct {
	requestCallbck RequestCallback
	contact        *sip.ContactHeader
	status         Status
	callID         sip.CallID
	offer          string
	answer         string
	request        sip.Request
	response       sip.Response
	transaction    sip.Transaction
	direction      Direction
	uaType         string // UAS | UAC
	remoteURI      sip.Address
	localURI       sip.Address
	remoteTarget   sip.Uri
	userData       *interface{}
}

func NewInviteSession(reqcb RequestCallback, uaType string, contact *sip.ContactHeader, req sip.Request, cid sip.CallID, tx sip.Transaction, dir Direction) *Session {
	s := &Session{
		requestCallbck: reqcb,
		uaType:         uaType,
		callID:         cid,
		transaction:    tx,
		direction:      dir,
		contact:        contact,
		offer:          "",
		answer:         "",
	}

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
	} else if uaType == "UAC" {
		s.localURI = sip.Address{Uri: from.Address, Params: from.Params}
		s.remoteURI = sip.Address{Uri: to.Address, Params: to.Params}
		s.remoteTarget = req.Recipient()
	}

	s.request = req
	return s
}

func (s *Session) String() string {
	return "Local: " + s.localURI.String() + ", Remote: " + s.remoteURI.String()
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
	case Terminated:
		return true
	default:
		return false
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
	s.status = status
}

func (s *Session) Status() Status {
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

//Info Send Info
func (s *Session) Info(content *sip.String) {

}

//ReInvite send re-INVITE
func (s *Session) ReInvite() {

}

//Bye send Bye request.
func (s *Session) Bye() {
	bye := s.makeByeRequest(s.uaType, sip.MessageID(s.callID), s.request, s.response)
	logger.Infof(s.uaType+" build request: %v => \n%v", sip.BYE, bye)
	s.requestCallbck(context.TODO(), bye, nil)
}

// Reject Reject incoming call or for re-INVITE or UPDATE,
func (s *Session) Reject(statusCode sip.StatusCode, reason string) {
	tx := (s.transaction.(sip.ServerTransaction))
	request := s.request
	logger.Infof("Reject: Request => %s, body => %s", request.Short(), request.Body())
	response := sip.NewResponseFromRequest(request.MessageID(), request, statusCode, reason, "")
	tx.Respond(response)
}

//End end session
func (s *Session) End() error {

	if s.status == Terminated {
		err := fmt.Errorf("Invalid status: %v", s.status)
		logger.Errorf("Session::End() %v", err)
		return err
	}

	switch s.status {
	// - UAC -
	case InviteSent:
		fallthrough
	case Provisional:
		fallthrough
	case EarlyMedia:
		logger.Info("Canceling session.")
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
		logger.Info("Rejecting session")
		s.Reject(603, "Decline")

	case WaitingForACK:
		fallthrough
	case Confirmed:
		logger.Info("Terminating session.")
		s.Bye()
	}

	return nil
}

// Accept 200
func (s *Session) Accept(statusCode sip.StatusCode) {
	tx := (s.transaction.(sip.ServerTransaction))

	if len(s.answer) == 0 {
		logger.Errorf("Answer sdp is nil!")
		return
	}
	request := s.request
	response := sip.NewResponseFromRequest(request.MessageID(), request, 200, "OK", s.answer)

	hdrs := request.GetHeaders("Content-Type")
	if len(hdrs) == 0 {
		contentType := sip.ContentType("application/sdp")
		response.AppendHeader(&contentType)
	} else {
		sip.CopyHeaders("Content-Type", request, response)
	}

	response.AppendHeader(s.localURI.AsContactHeader())
	s.response = response
	tx.Respond(response)

	s.SetState(WaitingForACK)
}

// Redirect send a 3xx
func (s *Session) Redirect(addr *sip.Address, code sip.StatusCode) {

}

// Provisional send a provisional code 100|180|183
func (s *Session) Provisional(statusCode sip.StatusCode, reason string) {
	tx := (s.transaction.(sip.ServerTransaction))
	request := s.request
	var response sip.Response
	if len(s.answer) > 0 {
		response = sip.NewResponseFromRequest(request.MessageID(), request, statusCode, reason, s.answer)
		hdrs := response.GetHeaders("Content-Type")
		if len(hdrs) == 0 {
			contentType := sip.ContentType("application/sdp")
			response.AppendHeader(&contentType)
		} else {
			sip.CopyHeaders("Content-Type", request, response)
		}
	} else {
		response = sip.NewResponseFromRequest(request.MessageID(), request, statusCode, reason, "")
	}

	s.response = response
	tx.Respond(response)
}

func (s *Session) makeByeRequest(uaType string, msgID sip.MessageID, inviteRequest sip.Request, inviteResponse sip.Response) sip.Request {
	byeRequest := sip.NewRequest(
		msgID,
		sip.BYE,
		s.remoteTarget,
		inviteRequest.SipVersion(),
		[]sip.Header{},
		"",
		inviteRequest.Fields().
			WithFields(log.Fields{
				"invite_request_id": inviteRequest.MessageID(),
			}),
	)

	if uaType == "UAC" {
		sip.CopyHeaders("Via", inviteRequest, byeRequest)
		if len(inviteRequest.GetHeaders("Route")) > 0 {
			sip.CopyHeaders("Route", inviteRequest, byeRequest)
		}
		sip.CopyHeaders("From", inviteRequest, byeRequest)
		sip.CopyHeaders("To", inviteResponse, byeRequest)
	} else if uaType == "UAS" {
		sip.CopyHeaders("Via", inviteRequest, byeRequest)
		if len(inviteResponse.GetHeaders("Route")) > 0 {
			sip.CopyHeaders("Route", inviteResponse, byeRequest)
		}
		sip.CopyHeaders("From", inviteResponse, byeRequest)
		sip.CopyHeaders("To", inviteRequest, byeRequest)
		byeRequest.SetDestination(inviteResponse.Destination())
		byeRequest.SetSource(inviteResponse.Source())
	}

	maxForwardsHeader := sip.MaxForwards(70)
	byeRequest.AppendHeader(&maxForwardsHeader)
	sip.CopyHeaders("Call-ID", inviteRequest, byeRequest)
	sip.CopyHeaders("CSeq", inviteRequest, byeRequest)
	cseq, _ := byeRequest.CSeq()
	cseq.MethodName = sip.BYE

	return byeRequest
}
