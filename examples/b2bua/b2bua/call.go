package b2bua

import (
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/ghettovoice/gosip/sip"
)

type CallState string

const (
	New        CallState = "New"
	Connecting CallState = "Connecting"
	Ringing    CallState = "Ringing"
	EarlyMedia CallState = "EarlyMedia"
	Confirmed  CallState = "Confirmed"
	Failure    CallState = "Failure"
	Terminated CallState = "Terminated"
)

func (s CallState) String() string {
	return string(s)
}

type Call struct {
	// sip session
	sess *session.Session
	// media transport
	mediaTransport MediaTransport

	originalMediaDesc *MediaDescription
}

func (b *Call) Init(transType MediaTransportType, md *MediaDescription) {
	b.originalMediaDesc = md

	if transType == TransportTypeWebRTC {
		b.mediaTransport = NewWebRTCMediaTransport(md)
	} else {
		b.mediaTransport = NewStandardMediaTransport(md)
	}

	b.mediaTransport.Init(b2buaConfig.UaMediaConfig)
}

func (b *Call) Id() string {
	return string(b.sess.CallID())
}

func (b *Call) ToString() string {
	return (b.sess.CallID()).String() + ", uri: " + b.sess.Contact()
}

func (b *Call) MediaInfo() string {
	info := "[" + b.mediaTransport.Type().String() + "]"
	for _, trackInfo := range b.originalMediaDesc.Tracks {
		info += trackInfo.String() + " "
	}
	return info
}

func (b *Call) Provisional(statusCode sip.StatusCode, reason string) {
	b.sess.Provisional(statusCode, reason)
}

func (b *Call) Reject(statusCode sip.StatusCode, reason string) {
	b.sess.Reject(statusCode, reason)
}

func (b *Call) Accept(answer string) {
	if aLegAnswer, err := b.mediaTransport.CreateAnswer(); err != nil {
		logger.Errorf("CreateAnswer failed: %v", err)
		return
	} else {
		// for sdp fix
		replaceCodec(aLegAnswer, answer)
		b.sess.ProvideAnswer(aLegAnswer.SDP)
	}
	b.sess.Accept(200)
}

func (b *Call) Terminate() {
	if b.sess.IsEstablished() {
		b.sess.Bye()
	} else if b.sess.IsInProgress() {
		b.sess.End()
	}
	b.mediaTransport.OnRtpPacket(nil)
	b.mediaTransport.OnRtcpPacket(nil)
	if err := b.mediaTransport.Close(); err != nil {
		logger.Errorf("Close media transport error: %v", err)
	}
}

func (b *Call) OnOffer(sdp *Desc) error {
	err := b.mediaTransport.OnOffer(sdp)
	if err != nil {
		logger.Errorf("OnOffer error: %v", err)
		return err
	}
	logger.Debugf("OnOffer: %v", sdp.SDP)
	return nil
}

func (b *Call) CreateOffer() (*Desc, error) {
	offer, err := b.mediaTransport.CreateOffer()
	if err != nil {
		logger.Errorf("Offer error: %v", err)
		return nil, err
	}
	logger.Debugf("CreateOffer: %v", offer.SDP)
	return offer, nil
}

func (b *Call) OnAnswer(sdp *Desc) error {
	err := b.mediaTransport.OnAnswer(sdp)
	if err != nil {
		logger.Errorf("OnAnswer error: %v", err)
		return err
	}
	logger.Debugf("OnAnswer: %v", sdp.SDP)
	return nil
}

func (b *Call) CreateAnswer() (*Desc, error) {
	answer, err := b.mediaTransport.CreateAnswer()
	if err != nil {
		logger.Errorf("Answer error: %v", err)
		return nil, err
	}
	logger.Debugf("CreateAnswer: %v", answer.SDP)
	return answer, nil
}
