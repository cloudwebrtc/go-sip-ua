package b2bua

import (
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
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

type Call struct {
	// sip session
	sess *session.Session
	// media transport
	mediaTransport MediaTransport

	srcTrackInfos []*TrackInfo
}

func (b *Call) Init(transType MediaTransportType, trackInfos []*TrackInfo) {
	b.srcTrackInfos = trackInfos

	if transType == TransportTypeWebRTC {
		b.mediaTransport = NewWebRTCMediaTransport(trackInfos)
	} else {
		b.mediaTransport = NewStandardMediaTransport(trackInfos)
	}

	b.mediaTransport.Init(callConfig)
}

func (b *Call) Id() string {
	return string(b.sess.CallID())
}

func (b *Call) ToString() string {
	return (b.sess.CallID()).String() + ", uri: " + b.sess.Contact()
}

func (b *Call) Accept(answer string) {
	if aLegAnswer, err := b.mediaTransport.CreateAnswer(); err != nil {
		logger.Errorf("Create A-Leg Answer failed: %v", err)
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
	/*
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
	*/

	err := b.mediaTransport.OnOffer(sdp)
	if err != nil {
		logger.Errorf("OnOffer error: %v", err)
		return err
	}
	return nil
}

func (b *Call) CreateOffer() (*Desc, error) {
	/*
		var trans MediaTransport

		if tpType == TransportTypeWebRTC {
			trans = NewWebRTCMediaTransport(b.srcTrackInfos)
		} else {
			trans = NewStandardMediaTransport("out-"+string(*b.src.CallID()), b.srcTrackInfos)
		}

		err := trans.Init(callConfig)

		if err != nil {
			logger.Errorf("Init transport error: %v", err)
			return nil, err
		}

		b.destTrans = trans
	*/
	offer, err := b.mediaTransport.CreateOffer()
	if err != nil {
		logger.Errorf("Offer error: %v", err)
		return nil, err
	}
	return offer, nil
}

func (b *Call) OnAnswer(sdp *Desc) error {
	err := b.mediaTransport.OnAnswer(sdp)
	if err != nil {
		logger.Errorf("OnAnswer error: %v", err)
		return err
	}

	return nil
}

func (b *Call) CreateAnswer() (*Desc, error) {
	answer, err := b.mediaTransport.CreateAnswer()
	if err != nil {
		logger.Errorf("Answer error: %v", err)
		return nil, err
	}
	return answer, nil
}
