package b2bua

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

	OnRtpPacket(rtpHandler func(trackType TrackType, payload []byte) (int, error))
	OnRtcpPacket(rtcpHandler func(trackType TrackType, payload []byte) (int, error))

	OnRequestKeyFrame(func() error)

	WriteRTP(trackType TrackType, payload []byte) (int, error)
	WriteRTCP(trackType TrackType, payload []byte) (int, error)

	RequestKeyFrame() error
}
