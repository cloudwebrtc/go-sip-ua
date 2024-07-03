package b2bua

import (
	"fmt"

	"github.com/pixelbender/go-sdp/sdp"
)

type TrackType string

const (
	TrackTypeAudio TrackType = "audio"
	TrackTypeVideo TrackType = "video"
)

func (t TrackType) String() string {
	return string(t)
}

type TrackInfo struct {
	TrackType  TrackType
	Codecs     []*sdp.Format
	Connection *sdp.Connection
	Direction  string
	Port       int
	RtcpPort   int
}

func (t *TrackInfo) String() string {
	return t.TrackType.String() + ": " + t.Codecs[0].Name + "/" + fmt.Sprintf("%d", t.Codecs[0].ClockRate) + ", pt: " + fmt.Sprintf("%d", t.Codecs[0].Payload)
}
