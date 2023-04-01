package b2bua

import (
	"fmt"

	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/pixelbender/go-sdp/sdp"
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

type Desc struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

func (d *Desc) Parse() (*sdp.Session, error) {
	return sdp.Parse([]byte(d.SDP))
}

func (d *Desc) FromSdpSession(sess *sdp.Session) error {
	d.SDP = sess.String()
	return nil
}

type B2BCall struct {
	ua   *ua.UserAgent
	src  *session.Session
	dest *session.Session

	trans map[*session.Session]Transport

	state CallState

	srcTrackInfos []*TrackInfo
}

func (b *B2BCall) ToString() string {
	return b.src.Contact() + " => " + b.dest.Contact()
}

func (b *B2BCall) Init() {
	b.state = New
	b.trans = make(map[*session.Session]Transport)
}

func (b *B2BCall) State() CallState {
	return b.state
}

func (b *B2BCall) SetState(state CallState) {
	b.state = state
}

func (b *B2BCall) Terminate() {
	for _, trans := range b.trans {
		if err := trans.Close(); err != nil {
			logger.Errorf("Close transport error: %v", err)
		}
	}
}

func (b *B2BCall) SetALegOffer(sdp *Desc) error {

	sdpSess, _ := sdp.Parse()
	transType := ParseTransportType(sdpSess)
	logger.Infof("TransportType: %v", transType)
	trackInfos, err := ParseTrackInfos(sdpSess)
	if err != nil {
		logger.Errorf("ParseTrackInfos error: %v", err)
		return err
	}

	logger.Infof("TrackInfos: %v", trackInfos)
	b.srcTrackInfos = trackInfos
	print(sdpSess.String())

	var trans Transport
	if transType == TransportTypeRTC {
		trans = NewWebRTCTransport(trackInfos)
	} else {
		trans = NewUdpTansport(trackInfos)
	}

	err = trans.Init(callConfig)

	if err != nil {
		logger.Errorf("Init transport error: %v", err)
		return err
	}

	err = trans.OnOffer(sdp)
	if err != nil {
		logger.Errorf("OnOffer error: %v", err)
		return err
	}

	b.trans[b.src] = trans
	return nil
}

func (b *B2BCall) CreateBLegOffer() (*Desc, error) {
	//TODO: create transport by b.srcOffer
	trans := NewUdpTansport(b.srcTrackInfos)

	err := trans.Init(callConfig)

	if err != nil {
		logger.Errorf("Init transport error: %v", err)
		return nil, err
	}

	b.trans[b.dest] = trans

	offer, err := trans.CreateOffer()
	if err != nil {
		logger.Errorf("Offer error: %v", err)
		return nil, err
	}
	return offer, nil
}

func (b *B2BCall) SetBLegAnswer(sdp *Desc) error {

	if trans, found := b.trans[b.dest]; found {
		err := trans.OnAnswer(sdp)
		if err != nil {
			logger.Errorf("OnAnswer error: %v", err)
			return err
		}
	} else {
		logger.Errorf("Transport not found")
		return fmt.Errorf("Transport not found")
	}

	return nil
}

func (b *B2BCall) CreateALegAnswer() (*Desc, error) {
	if trans, found := b.trans[b.src]; found {
		answer, err := trans.CreateAnswer()
		if err != nil {
			logger.Errorf("Answer error: %v", err)
			return nil, err
		}
		return answer, nil
	} else {
		logger.Errorf("Transport not found")
		return nil, fmt.Errorf("Transport not found")
	}
}

type TransportType string

const (
	TransportTypeSIP     TransportType = "SIP"
	TransportTypeRTC     TransportType = "WebRTC"
	TransportTypeUnknown TransportType = "Unknown"
)

type Transport interface {
	Init(config CallConfig) error
	Close() error
	CreateOffer() (*Desc, error)
	OnAnswer(desc *Desc) error
	OnOffer(sdp *Desc) error
	CreateAnswer() (*Desc, error)
	Type() TransportType
}
