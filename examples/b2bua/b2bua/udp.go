package b2bua

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/util"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pixelbender/go-sdp/sdp"
)

type UdpTansport struct {
	trackInfos        []*TrackInfo
	ports             map[TrackType]*UdpPort
	localDescription  *sdp.Session
	remoteDescription *sdp.Session

	mu          sync.RWMutex
	rtpHandler  func(trackType TrackType, payload []byte)
	rtcpHandler func(trackType TrackType, payload []byte)

	videoSSRC uint32
	closed    utils.AtomicBool
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewUdpTansport(trackInfos []*TrackInfo) *UdpTansport {
	t := &UdpTansport{
		trackInfos: trackInfos,
		ports:      make(map[TrackType]*UdpPort),
		videoSSRC:  0,
	}

	t.ctx, t.cancel = context.WithCancel(context.TODO())
	t.closed.Set(false)
	return t
}

func (c *UdpTansport) Init(config CallConfig) error {

	host := callConfig.ExternalRtpAddress

	if host == "" || host == "0.0.0.0" {
		if v, err := util.ResolveSelfIP(); err == nil {
			host = v.String()
		}
	}

	c.localDescription = &sdp.Session{
		Origin: &sdp.Origin{
			Username:       "-",
			Address:        host,
			SessionID:      time.Now().UnixNano() / 1e6,
			SessionVersion: time.Now().UnixNano() / 1e6,
		},
		Timing: &sdp.Timing{Start: time.Time{}, Stop: time.Time{}},
		//Name: "Example",
		Connection: &sdp.Connection{
			Address: host,
		},
		//Bandwidth: []*sdp.Bandwidth{{Type: "AS", Value: 117}},
	}

	var medias []*sdp.Media

	for _, trackInfo := range c.trackInfos {
		udpPort, err := NewUdpPort(trackInfo.TrackType, config.ExternalRtpAddress)
		if err != nil {
			return err
		}
		udpPort.Init()
		udpPort.OnRtpPacketReceived(c.onRtpPacket)
		udpPort.OnRtcpPacketReceived(c.onRtcpPacket)
		c.ports[trackInfo.TrackType] = udpPort

		media := &sdp.Media{}
		media.Type = string(trackInfo.TrackType)
		media.Port = udpPort.LocalPort()
		media.Proto = "RTP/AVP"
		media.Mode = sdp.SendRecv
		media.Connection = []*sdp.Connection{{Address: host}}
		//Bandwidth: []*sdp.Bandwidth{{Type: "TIAS", Value: 96000}},

		var formats []*sdp.Format
		for _, codec := range trackInfo.Codecs {
			for _, enabledCodec := range callConfig.Codecs {
				if codec.Name == enabledCodec {
					formats = append(formats, &sdp.Format{
						Payload:   codec.Payload,
						Name:      codec.Name,
						ClockRate: codec.ClockRate,
						Params:    codec.Params,
						//Feedback:  codec.Feedback,
					})
				}
			}

		}
		media.Format = formats
		medias = append(medias, media)
	}

	c.localDescription.Media = medias
	return nil
}

func (c *UdpTansport) OnRtpPacket(rtpHandler func(trackType TrackType, payload []byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rtpHandler = rtpHandler
}

func (c *UdpTansport) OnRtcpPacket(rtcpHandler func(trackType TrackType, payload []byte)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rtcpHandler = rtcpHandler
}

func (c *UdpTansport) onRtpPacket(trackType TrackType, packet []byte, raddr net.Addr) error {
	logger.Debugf("UdpTansport::OnRtpPacketReceived: %v read %d bytes, raddr %v", trackType, len(packet), raddr)

	p := &rtp.Packet{}
	if err := p.Unmarshal(packet); err != nil {
		logger.Errorf("rtp.Packet Unmarshal: e %v len %v", err, len(packet))
	}

	logger.Debugf("UdpTansport::onRtpPacket: [%v] read %d bytes, seq %d, ts %d, ssrc %v, payload %v", trackType, len(packet), p.SequenceNumber, p.Timestamp, p.SSRC, p.PayloadType)

	if trackType == TrackTypeVideo && c.videoSSRC == 0 {
		c.videoSSRC = p.SSRC
		c.RequestKeyFrame(c.videoSSRC)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rtpHandler != nil {
		c.rtpHandler(trackType, packet)
	}
	return nil
}

func (c *UdpTansport) onRtcpPacket(trackType TrackType, packet []byte, raddr net.Addr) error {
	logger.Debugf("UdpTansport::OnRtcpPacketReceived: %v read %d bytes, raddr %v", trackType, len(packet), raddr)
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rtcpHandler != nil {
		c.rtcpHandler(trackType, packet)
	}
	return nil
}

func (c *UdpTansport) WriteRTP(trackType TrackType, packet []byte) (int, error) {

	p := &rtp.Packet{}
	if err := p.Unmarshal(packet); err != nil {
		logger.Errorf("tp.Packet Unmarshal: e %v", err)
	}
	logger.Debugf("UdpTansport::WriteRTP: %v, write %d bytes, seq %d, ts %d", trackType, len(packet), p.SequenceNumber, p.Timestamp)

	p.Extension = false
	p.ExtensionProfile = 0
	p.Extensions = nil
	p.Padding = false
	p.PaddingSize = 0

	if trackType == TrackTypeVideo {
		p.PayloadType = 98
	}

	pktbuf, err := p.Marshal()

	if err != nil {
		logger.Errorf("Marshal rtp receiver packets err %v", err)
	}

	port := c.ports[trackType]
	raddr := port.GetRemoteRtpAddress()
	if raddr == nil {
		logger.Errorf("raddr is nil")
		return 0, nil
	}

	logger.Debugf("UdpTansport::WriteRTP: %v, raddr %v", trackType, *raddr)
	return port.WriteRtpPacket(pktbuf, *raddr)
}

func (c *UdpTansport) WriteRTCP(trackType TrackType, packet []byte) (int, error) {

	pkts, err := rtcp.Unmarshal(packet)
	if err != nil {
		logger.Errorf("Unmarshal rtcp receiver packets err %v", err)
	}

	logger.Debugf("UdpTansport::WriteRTCP: %v read %d packets", trackType, len(pkts))

	port := c.ports[trackType]
	raddr := port.GetRemoteRtcpAddress()
	if raddr == nil {
		logger.Errorf("raddr is nil")
		raddr = port.GetRemoteRtpAddress()
	}
	logger.Infof("UdpTansport::WriteRTCP: %v read %d packets, raddr %v", trackType, len(pkts), *raddr)
	return port.WriteRtcpPacket(packet, *raddr)
}

func (c *UdpTansport) Type() TransportType {
	return TransportTypeSIP
}

func (c *UdpTansport) Close() error {

	c.mu.Lock()
	defer c.mu.Unlock()

	c.rtcpHandler = nil
	c.rtpHandler = nil

	if !c.closed.Get() {
		c.closed.Set(true)
	}
	c.cancel()

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
	/*
		=0
		o=100 703 1242 IN IP4 192.168.1.154
		s=Talk
		c=IN IP4 192.168.1.154
		t=0 0
		m=audio 40063 RTP/AVP 0 8 116
		a=rtpmap:116 telephone-event/8000
		a=rtcp:49374
		m=video 47878 RTP/AVP 96
		a=rtpmap:96 H264/90000
		a=fmtp:96 profile-level-id=42801F; packetization-mode=1
		a=rtcp:37679
	*/
	conn := sess.Connection
	if conn != nil {
		logger.Infof("remote connection address: %s", conn.Address)
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

func (c *UdpTansport) RequestKeyFrame(ssrc uint32) error {
	go func() {
		ticker := time.NewTicker(time.Second * 3)
		for range ticker.C {
			if c.closed.Get() {
				logger.Infof("Terminate: stop pli loop now!")
				return
			}
			pli := rtcp.PictureLossIndication{MediaSSRC: uint32(ssrc)}
			buf, err := pli.Marshal()
			if err != nil {
				logger.Error(err)
				return
			}
			_, errSend := c.WriteRTCP(TrackTypeVideo, buf)
			if errSend != nil {
				logger.Error(errSend)
				return
			}
			logger.Infof("Sent PLI %v", pli)
		}
	}()
	return nil
}
