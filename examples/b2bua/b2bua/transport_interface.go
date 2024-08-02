package b2bua

import (
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

type MediaTransportType string

const (
	TransportTypeStandard MediaTransportType = "Standard-AVP/RTP/UDP"
	TransportTypeWebRTC   MediaTransportType = "WebRTC-SAVPF/DTLS/SRTP"
)

func (t MediaTransportType) String() string {
	return string(t)
}

type MediaTransport interface {
	Init(umc UserAgentMediaConfig) error
	Close() error
	CreateOffer() (*Desc, error)
	OnAnswer(desc *Desc) error
	OnOffer(sdp *Desc) error
	CreateAnswer() (*Desc, error)
	Type() MediaTransportType

	OnRtpPacket(rtpHandler func(trackType TrackType, pkt rtp.Packet) (int, error))
	OnRtcpPacket(rtcpHandler func(trackType TrackType, pkt rtcp.Packet) (int, error))

	OnRequestKeyFrame(func() error)

	WriteRTP(trackType TrackType, pkt rtp.Packet) (int, error)
	WriteRTCP(trackType TrackType, pkt rtcp.Packet) (int, error)

	RequestKeyFrame() error
}
