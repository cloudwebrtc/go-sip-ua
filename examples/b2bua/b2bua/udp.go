package b2bua

import (
	"net"
	"time"

	"github.com/pixelbender/go-sdp/sdp"
)

type UdpTansport struct {
	trackInfos        []*TrackInfo
	ports             map[TrackType]*UdpPort
	localDescription  *sdp.Session
	remoteDescription *sdp.Session
}

func NewUdpTansport(trackInfos []*TrackInfo) *UdpTansport {
	return &UdpTansport{
		trackInfos: trackInfos,
		ports:      make(map[TrackType]*UdpPort),
	}
}

func (c *UdpTansport) Init(config CallConfig) error {

	for _, trackInfo := range c.trackInfos {
		udpPort, err := NewUdpPort(trackInfo.TrackType, config.ExternalRtpAddress)
		if err != nil {
			return err
		}
		udpPort.Init()
		udpPort.OnRtpPacketReceived(func(packet []byte, raddr net.Addr) {
			c.OnRtpPacketReceived(trackInfo.TrackType, packet, raddr)
		})
		udpPort.OnRtcpPacketReceived(func(packet []byte, raddr net.Addr) {
			c.OnRtcpPacketReceived(trackInfo.TrackType, packet, raddr)
		})
		c.ports[trackInfo.TrackType] = udpPort
	}

	c.localDescription = &sdp.Session{
		Origin: &sdp.Origin{
			Username:       "-",
			Address:        callConfig.ExternalRtpAddress,
			SessionID:      time.Now().UnixNano() / 1e6,
			SessionVersion: time.Now().UnixNano() / 1e6,
		},
		Timing: &sdp.Timing{Start: time.Time{}, Stop: time.Time{}},
		//Name: "Example",
		Connection: &sdp.Connection{
			Address: callConfig.ExternalRtpAddress,
		},
		//Bandwidth: []*sdp.Bandwidth{{Type: "AS", Value: 117}},
		Media: []*sdp.Media{
			{
				//Bandwidth: []*sdp.Bandwidth{{Type: "TIAS", Value: 96000}},
				Connection: []*sdp.Connection{{Address: callConfig.ExternalRtpAddress}},
				Mode:       sdp.SendRecv,
				Type:       "audio",
				Port:       c.ports[TrackTypeAudio].LocalPort(),
				Proto:      "RTP/AVP",
				Format: []*sdp.Format{
					{Payload: 0, Name: "PCMU", ClockRate: 8000},
					{Payload: 8, Name: "PCMA", ClockRate: 8000},
					//{Payload: 18, Name: "G729", ClockRate: 8000, Params: []string{"annexb=yes"}},
					{Payload: 116, Name: "telephone-event", ClockRate: 8000, Params: []string{"0-16"}},
				},
			},
			{
				//Bandwidth: []*sdp.Bandwidth{{Type: "TIAS", Value: 96000}},
				Connection: []*sdp.Connection{{Address: callConfig.ExternalRtpAddress}},
				Mode:       sdp.SendRecv,
				Type:       "video",
				Port:       c.ports[TrackTypeVideo].LocalPort(),
				Proto:      "RTP/AVP",
				Format: []*sdp.Format{
					{Payload: 96, Name: "H264", ClockRate: 90000, Params: []string{"packetization-mode=1"}},
				},
			},
		},
	}
	return nil
}

func (c *UdpTansport) OnRtpPacketReceived(trackType TrackType, packet []byte, raddr net.Addr) error {
	return nil
}

func (c *UdpTansport) OnRtcpPacketReceived(trackType TrackType, packet []byte, raddr net.Addr) error {
	return nil
}

func (c UdpTansport) WriteRtpPacket(trackType TrackType, packet []byte) error {
	udpPort := c.ports[trackType]
	raddr := udpPort.GetRemoteRtpAddress()
	return udpPort.WriteRtpPacket(packet, *raddr)
}

func (c UdpTansport) WriteRtcpPacket(trackType TrackType, packet []byte) error {
	udpPort := c.ports[trackType]
	raddr := udpPort.GetRemoteRtcpAddress()
	return udpPort.WriteRtpPacket(packet, *raddr)
}

func (c *UdpTansport) Type() TransportType {
	return TransportTypeSIP
}

func (c *UdpTansport) Close() error {
	for _, udpPort := range c.ports {
		udpPort.Close()
	}

	return nil
}

func (c *UdpTansport) CreateOffer() (*Desc, error) {
	return &Desc{
		Type: "offer",
		SDP:  c.localDescription.String(),
	}, nil
}

func (c *UdpTansport) OnAnswer(answer *Desc) error {
	sess, err := sdp.Parse([]byte(answer.SDP))
	if err != nil {
		return err
	}
	c.remoteDescription = sess
	return nil
}

func (c *UdpTansport) OnOffer(offer *Desc) error {
	sess, err := sdp.Parse([]byte(offer.SDP))
	if err != nil {
		return err
	}
	c.remoteDescription = sess

	return nil
}

func (c *UdpTansport) CreateAnswer() (*Desc, error) {
	return &Desc{
		Type: "offer",
		SDP:  c.localDescription.String(),
	}, nil
}
