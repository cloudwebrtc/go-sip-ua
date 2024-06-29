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
	Direction  string
	Port       int
	RtcpPort   int
}
