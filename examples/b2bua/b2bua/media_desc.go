package b2bua

import (
	"errors"
	"fmt"

	"github.com/pixelbender/go-sdp/sdp"
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

type TransportType string

const (
	MediaTransportUDP  TransportType = "UDP"
	MediaTransportTCP  TransportType = "TCP"
	MediaTransportTLS  TransportType = "TLS"
	MediaTransportDTLS TransportType = "DTLS"
)

type MediaStreamDir string

const (
	MediaStreamSendRecv MediaStreamDir = "sendrecv"
	MediaStreamSendOnly MediaStreamDir = "sendonly"
	MediaStreamRecvOnly MediaStreamDir = "recvonly"
	MediaStreamInactive MediaStreamDir = "inactive"
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
	TrackType TrackType
	Codecs    []*sdp.Format
	Direction string
	Port      int
	RtcpPort  int
	Ssrc      uint32
}

func (t *TrackInfo) String() string {
	return t.TrackType.String() + ": " + t.Codecs[0].Name + "/" + fmt.Sprintf("%d", t.Codecs[0].ClockRate) + ", pt: " + fmt.Sprintf("%d", t.Codecs[0].Payload)
}

type MediaDescription struct {
	Tracks     map[TrackType]*TrackInfo
	Connection *sdp.Connection
}

func MediaDescriptionFrom(sdp *Desc) (*MediaDescription, error) {
	sess, err := sdp.Parse()
	if err != nil {
		return nil, err
	}
	md, err := ParseMediaDescription(sess)
	if err != nil {
		return nil, err
	}
	return md, nil
}

func ParseMediaDescription(sdp *sdp.Session) (*MediaDescription, error) {
	if sdp == nil {
		return nil, errors.New("sdp is nil")
	}
	mediaDesc := &MediaDescription{
		Connection: sdp.Connection,
		Tracks:     make(map[TrackType]*TrackInfo),
	}
	for _, m := range sdp.Media {
		trackInfo := &TrackInfo{
			Ssrc:      0,
			Direction: m.Mode,
			Port:      m.Port,
		}

		if trackInfo.Port > 0 {
			trackInfo.RtcpPort = m.Port + 1
		}
		trackInfo.Codecs = fixFormatName(m.Format)
		if m.Type == "audio" {
			trackInfo.TrackType = TrackTypeAudio
		} else if m.Type == "video" {
			trackInfo.TrackType = TrackTypeVideo
		} else {
			continue
		}
		mediaDesc.Tracks[trackInfo.TrackType] = trackInfo
	}

	return mediaDesc, nil
}

func Negotiation(local *MediaDescription, remote *MediaDescription) (*MediaDescription, error) {

	return nil, nil
}
