package b2bua

import (
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

	srcTrans  Transport
	destTrans Transport

	state CallState

	srcTrackInfos []*TrackInfo
}

func (b *B2BCall) ToString() string {
	return b.src.Contact() + " => " + b.dest.Contact()
}

func (b *B2BCall) Init() {
	b.state = New
}

func (b *B2BCall) State() CallState {
	return b.state
}

func (b *B2BCall) SetState(state CallState) {
	b.state = state
}

func (b *B2BCall) Terminate(sess *session.Session) {

	b.srcTrans.OnRtpPacket(nil)
	b.destTrans.OnRtpPacket(nil)

	b.srcTrans.OnRtcpPacket(nil)
	b.destTrans.OnRtcpPacket(nil)

	if err := b.srcTrans.Close(); err != nil {
		logger.Errorf("Close src transport error: %v", err)
	}

	if err := b.destTrans.Close(); err != nil {
		logger.Errorf("Close dest transport error: %v", err)
	}

	if b.src == sess {
		if b.state != Confirmed {
			b.dest.End()
		} else {
			b.dest.Bye()
		}
	} else if b.dest == sess {
		if b.state != Confirmed {
			b.src.End()
		} else {
			b.src.Bye()
		}
	}
	b.state = Terminated
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

	b.srcTrans = trans
	return nil
}

func (b *B2BCall) CreateBLegOffer(tpType TransportType) (*Desc, error) {

	var trans Transport

	if tpType == TransportTypeRTC {
		trans = NewWebRTCTransport(b.srcTrackInfos)
	} else {
		trans = NewUdpTansport(b.srcTrackInfos)
	}

	err := trans.Init(callConfig)

	if err != nil {
		logger.Errorf("Init transport error: %v", err)
		return nil, err
	}

	b.destTrans = trans

	offer, err := trans.CreateOffer()
	if err != nil {
		logger.Errorf("Offer error: %v", err)
		return nil, err
	}
	return offer, nil
}

func (b *B2BCall) SetBLegAnswer(sdp *Desc) error {
	err := b.destTrans.OnAnswer(sdp)
	if err != nil {
		logger.Errorf("OnAnswer error: %v", err)
		return err
	}

	return nil
}

func (b *B2BCall) CreateALegAnswer() (*Desc, error) {
	answer, err := b.srcTrans.CreateAnswer()
	if err != nil {
		logger.Errorf("Answer error: %v", err)
		return nil, err
	}
	return answer, nil
}

func (b *B2BCall) BridgeMediaStream() error {
	b.srcTrans.OnRtpPacket(func(trackType TrackType, payload []byte) {
		_, err := b.destTrans.WriteRTP(trackType, payload)
		if err != nil {
			logger.Errorf("WriteRTP[%v] %v error: %v", b.destTrans.Type(), trackType, err)
		}
	})
	b.srcTrans.OnRtcpPacket(func(trackType TrackType, payload []byte) {
		_, err := b.destTrans.WriteRTCP(trackType, payload)
		if err != nil {
			logger.Errorf("WriteRTCP[%v] %v error: %v", b.destTrans.Type(), trackType, err)
		}
	})
	b.srcTrans.OnRequestKeyFrame(func() {
		err := b.destTrans.RequestKeyFrame()
		if err != nil {
			logger.Errorf("OnRequestKeyFrame[%v]  error: %v", b.destTrans.Type(), err)
		}
	})

	b.destTrans.OnRtpPacket(func(trackType TrackType, payload []byte) {
		_, err := b.srcTrans.WriteRTP(trackType, payload)
		if err != nil {
			logger.Errorf("WriteRTP[%v] %v error: %v", b.srcTrans.Type(), trackType, err)
		}
	})
	b.destTrans.OnRtcpPacket(func(trackType TrackType, payload []byte) {
		_, err := b.srcTrans.WriteRTCP(trackType, payload)
		if err != nil {
			logger.Errorf("WriteRTCP[%v] %v error: %v", b.srcTrans.Type(), trackType, err)
		}
	})
	b.destTrans.OnRequestKeyFrame(func() {
		err := b.srcTrans.RequestKeyFrame()
		if err != nil {
			logger.Errorf("OnRequestKeyFrame[%v]  error: %v", b.srcTrans.Type(), err)
		}
	})
	return nil
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

	OnRtpPacket(rtpHandler func(trackType TrackType, payload []byte))
	OnRtcpPacket(rtcpHandler func(trackType TrackType, payload []byte))

	OnRequestKeyFrame(func())

	WriteRTP(trackType TrackType, payload []byte) (int, error)
	WriteRTCP(trackType TrackType, payload []byte) (int, error)

	RequestKeyFrame() error
}
