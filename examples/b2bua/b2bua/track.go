package b2bua

import "github.com/pixelbender/go-sdp/sdp"

type TrackType string

const (
	TrackTypeAudio TrackType = "audio"
	TrackTypeVideo TrackType = "video"
)

type TrackInfo struct {
	TrackType  TrackType
	Codecs     []*sdp.Format
	Connection *sdp.Connection
}

type Track interface {
	Type() TrackType

	Codec() string

	PayloadType() int

	WriteRtpPacket(packet []byte) error
	WriteRtcpPacket(packet []byte) error

	ReadRtpPacket(func(packet []byte) error) error
	ReadRtcpPacket(func(packet []byte) error) error

	RequestKeyFrame() error
}
