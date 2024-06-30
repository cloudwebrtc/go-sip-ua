package b2bua

type TransportType string

const (
	TransportTypeSIP TransportType = "SIP"
	TransportTypeRTC TransportType = "WebRTC"
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
