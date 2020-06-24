package invite

import (
	"context"
	"fmt"

	"github.com/cloudwebrtc/go-sip-ua/pkg/endpoint"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/util"
	"github.com/pixelbender/go-sdp/sdp"
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewDefaultLogrusLogger().WithPrefix("invite.Session")
}

type Status string

const (
	Null             Status = "Null"
	InviteSent       Status = "InviteSent"       /**< After INVITE s sent */
	InviteReceived   Status = "InviteReceived"   /**< After INVITE s received. */
	ReInviteReceived Status = "ReInviteReceived" /**< After re-INVITE/UPDATE s received */
	//Answer         Status = "Answer"         /**< After response for re-INVITE/UPDATE. */
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

type Session struct {
	edp          *endpoint.EndPoint
	contact      *sip.ContactHeader
	status       Status
	callID       sip.CallID
	offer        *sdp.Session
	answer       *sdp.Session
	request      sip.Request
	response     sip.Response
	transaction  sip.Transaction
	direction    Direction
	uaType       string // UAS | UAC
	remoteURI    sip.Address
	localURI     sip.Address
	remoteTarget sip.Uri
}

func NewInviteSession(edp *endpoint.EndPoint, uaType string, contact *sip.ContactHeader, req sip.Request, cid sip.CallID, tx sip.Transaction, dir Direction) *Session {
	s := &Session{
		edp:         edp,
		uaType:      uaType,
		callID:      cid,
		transaction: tx,
		direction:   dir,
		contact:     contact,
	}

	to, _ := req.To()
	from, _ := req.From()

	if !to.Params.Has("tag") {
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
		s.remoteTarget = contact.Address
	}
	s.request = req
	return s
}

func (s *Session) CallID() *sip.CallID {
	return &s.callID
}

func (s *Session) Request() sip.Request {
	return s.request
}

func (s *Session) isInProgress() bool {
	switch s.status {
	case Null:
		fallthrough
	case InviteSent:
		fallthrough
	case Provisional:
		fallthrough
	case InviteReceived:
		fallthrough
	case WaitingForAnswer:
		return true
	default:
		return false
	}
}

func (s *Session) isEstablished() bool {
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

func (s *Session) isEnded() bool {
	switch s.status {
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
	s.response = response
}

func (s *Session) StoreTransaction(tx sip.Transaction) {
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
func (s *Session) GetEarlyMedia() *sdp.Session {
	return s.answer
}

//ProvideOffer .
func (s *Session) ProvideOffer(sdp *sdp.Session) {
	s.offer = sdp
}

// ProvideAnswer .
func (s *Session) ProvideAnswer(sdp *sdp.Session) {
	s.answer = sdp
}

//Info Send Info
func (s *Session) Info(content *sip.String) {

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
		return fmt.Errorf("Invalid status: %v", s.status)
	}

	switch s.status {
	// - UAC -
	case Null:
		fallthrough
	case InviteSent:
		fallthrough
	case Provisional:
		fallthrough
	case EarlyMedia:
		logger.Info("Canceling session.")
		s.transaction.Done()

	// - UAS -
	case WaitingForAnswer:
		fallthrough
	case Answered:
		logger.Info("Rejecting session")
		s.Reject(603, "Decline")

	case WaitingForACK:
		fallthrough
	case Confirmed:
		logger.Info("Terminating session.")
		//Send Bye
		bye, err := s.MakeRequest(sip.BYE)
		if err != nil {
			logger.Errorf("bye => %v", err)
			return err
		}
		s.edp.RequestWithContext(context.TODO(), *bye, nil)
	}

	return nil
}

// Accept 200
func (s *Session) Accept(statusCode sip.StatusCode) {
	tx := (s.transaction.(sip.ServerTransaction))

	if s.answer == nil {
		logger.Errorf("Answer sdp is nil!")
		return
	}
	request := s.request
	response := sip.NewResponseFromRequest(request.MessageID(), request, 200, "OK", s.answer.String())

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
}

// Redirect send a 3xx
func (s *Session) Redirect(addr *sip.Address, code sip.StatusCode) {

}

// Provisional send a provisional code 100|180|183
func (s *Session) Provisional(statusCode sip.StatusCode, reason string) {
	tx := (s.transaction.(sip.ServerTransaction))
	request := s.request
	var response sip.Response
	if s.answer != nil {
		sdp := s.answer.String()
		response = sip.NewResponseFromRequest(request.MessageID(), request, statusCode, reason, sdp)
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

func (s *Session) MakeRequest(method sip.RequestMethod) (*sip.Request, error) {
	builder := sip.NewRequestBuilder().
		SetMethod(method).
		SetFrom(&s.localURI).
		SetTo(&s.remoteURI).
		SetRecipient(s.remoteTarget)
		//.AddVia(s.recordRoute[0])

	builder.SetCallID(&s.callID)
	builder.SetContact(&s.localURI)
	req, err := builder.Build()
	if err != nil {
		logger.Errorf("err => %v", err)
		return nil, err
	}

	logger.Infof("buildRequest %v => %v", method, req)
	return &req, err
}
