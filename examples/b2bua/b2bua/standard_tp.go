package b2bua

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/util"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pixelbender/go-sdp/sdp"
)

type StandardMediaTransport struct {
	md                *MediaDescription
	ports             map[TrackType]*UdpPort
	localDescription  *sdp.Session
	remoteDescription *sdp.Session

	mu                     sync.RWMutex
	rtpHandler             func(trackType TrackType, pkt rtp.Packet) (int, error)
	rtcpHandler            func(trackType TrackType, pkt rtcp.Packet) (int, error)
	requestKeyFrameHandler func() error

	videoSSRC uint32
	closed    utils.AtomicBool
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewStandardMediaTransport(md *MediaDescription) *StandardMediaTransport {
	t := &StandardMediaTransport{
		md:        md,
		ports:     make(map[TrackType]*UdpPort),
		videoSSRC: 0,
	}

	t.ctx, t.cancel = context.WithCancel(context.TODO())
	t.closed.Set(false)
	return t
}

func (c *StandardMediaTransport) Init(umc UserAgentMediaConfig) error {

	host := b2buaConfig.UaMediaConfig.ExternalRtpAddress

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
		//Name: "play", // Session Name ("s=")
		Connection: &sdp.Connection{
			Address: host,
		},
		//Bandwidth: []*sdp.Bandwidth{{Type: "AS", Value: 117}},
	}

	var medias []*sdp.Media

	for _, trackInfo := range c.md.Tracks {

		var rAddr *net.UDPAddr = nil
		var rRtcpAddr *net.UDPAddr = nil
		if c.md.Connection != nil {
			rAddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.md.Connection.Address, trackInfo.Port))
			rRtcpAddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.md.Connection.Address, trackInfo.RtcpPort))
		}

		udpPort, err := NewUdpPort(trackInfo.TrackType, rAddr, rRtcpAddr, umc.ExternalRtpAddress)
		if err != nil {
			return err
		}
		udpPort.Init()
		udpPort.OnRtpPacket(c.onRtpPacket)
		udpPort.OnRtcpPacket(c.onRtcpPacket)
		c.ports[trackInfo.TrackType] = udpPort

		media := &sdp.Media{}
		media.Type = string(trackInfo.TrackType)
		media.Port = udpPort.LocalPort()
		media.Proto = "RTP/AVP"
		media.Mode = trackInfo.Direction
		media.Connection = []*sdp.Connection{{Address: host}}
		//Bandwidth: []*sdp.Bandwidth{{Type: "TIAS", Value: 96000}},

		var formats []*sdp.Format
		for _, codec := range trackInfo.Codecs {
			for _, enabledCodec := range b2buaConfig.UaMediaConfig.Codecs {
				if codec.Name == enabledCodec {
					formats = append(formats, codec)
				}
			}
		}
		media.Format = formats
		medias = append(medias, media)
	}

	c.localDescription.Media = medias
	return nil
}

func (c *StandardMediaTransport) OnRtpPacket(rtpHandler func(trackType TrackType, pkt rtp.Packet) (int, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rtpHandler = rtpHandler
}

func (c *StandardMediaTransport) OnRtcpPacket(rtcpHandler func(trackType TrackType, pkt rtcp.Packet) (int, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rtcpHandler = rtcpHandler
}

func (c *StandardMediaTransport) OnRequestKeyFrame(keyHandler func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestKeyFrameHandler = keyHandler
}

func (c *StandardMediaTransport) onRtpPacket(trackType TrackType, packet []byte, raddr net.Addr) error {
	logger.Tracef("UdpTansport::onRtpPacket: %v read %d bytes, raddr %v", trackType, len(packet), raddr)

	p := rtp.Packet{}
	if err := p.Unmarshal(packet); err != nil {
		logger.Errorf("rtp.Packet Unmarshal: e %v len %v", err, len(packet))
	}

	logger.Tracef("UdpTansport::onRtpPacket: [%v] read %d bytes, seq %d, ts %d, ssrc %v, payload %v", trackType, len(packet), p.SequenceNumber, p.Timestamp, p.SSRC, p.PayloadType)

	if trackType == TrackTypeVideo && c.videoSSRC == 0 {
		c.videoSSRC = p.SSRC
		//c.sendPLI(c.videoSSRC)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rtpHandler != nil {
		if _, err := c.rtpHandler(trackType, p); err != nil {
			logger.Warnf("UdpTansport::onRtpPacket: panic => %v", err)
		}
	}
	return nil
}

func (c *StandardMediaTransport) onRtcpPacket(trackType TrackType, buf []byte, raddr net.Addr) error {
	logger.Tracef("UdpTansport::OnRtcpPacketReceived: %v read %d bytes, raddr %v", trackType, len(buf), raddr)
	c.mu.RLock()
	defer c.mu.RUnlock()

	pkts, err := rtcp.Unmarshal(buf)

	if err != nil {
		//logger.Warnf("UdpTansport::OnRtcpPacketReceived: Unmarshal rtcp receiver packets err %v", err)
		return err
	}

	if c.rtcpHandler != nil {
		for _, pkt := range pkts {
			if _, err := c.rtcpHandler(trackType, pkt); err != nil {
				logger.Warnf("UdpTansport::onRtcpPacket: panic => %v", err)
			}
		}
	}
	return nil
}

func (c *StandardMediaTransport) WriteRTP(trackType TrackType, pkt rtp.Packet) (int, error) {
	logger.Tracef("UdpTansport::WriteRTP: %v, write %d bytes", trackType, len(pkt.Payload))

	port := c.ports[trackType]

	if port == nil {
		logger.Errorf("UdpTansport::WriteRTP: port is nil")
		return 0, nil
	}

	track, found := c.md.Tracks[trackType]
	if !found {
		return 0, fmt.Errorf("track %v not found", trackType)
	}

	//re-write payload type
	pkt.PayloadType = track.Codecs[0].Payload
	pktbuf, err := pkt.Marshal()

	if err != nil {
		logger.Errorf("UdpTansport::WriteRTP: Marshal rtp receiver packets err %v", err)
	}

	return port.WriteRtp(pktbuf)
}

func (c *StandardMediaTransport) WriteRTCP(trackType TrackType, pkt rtcp.Packet) (int, error) {
	port := c.ports[trackType]

	if port == nil {
		logger.Errorf("UdpTansport::WriteRTCP: port is nil")
		return 0, nil
	}

	buf, err := pkt.Marshal()
	if err != nil {
		logger.Errorf("UdpTansport::WriteRTCP: Marshal rtcp receiver packets err %v", err)
		return 0, err
	}

	logger.Tracef("UdpTansport::WriteRTCP: %v, write %d bytes", trackType, len(buf))
	return port.WriteRtcp(buf)
}

func (c *StandardMediaTransport) Type() MediaTransportType {
	return TransportTypeStandard
}

func (c *StandardMediaTransport) Close() error {
	for _, udpPort := range c.ports {
		udpPort.Close()
	}

	return nil
}

func (c *StandardMediaTransport) CreateOffer() (*Desc, error) {
	return &Desc{
		Type: "offer",
		SDP:  c.localDescription.String(),
	}, nil
}

func (c *StandardMediaTransport) OnAnswer(answer *Desc) error {
	sess, err := sdp.Parse([]byte(answer.SDP))
	if err != nil {
		return err
	}
	conn := sess.Connection
	if conn != nil {
		logger.Debugf("remote connection address: %s", conn.Address)
	}
	c.md, _ = MediaDescriptionFrom(answer)
	c.remoteDescription = sess
	return nil
}

func (c *StandardMediaTransport) OnOffer(offer *Desc) error {
	sess, err := sdp.Parse([]byte(offer.SDP))
	if err != nil {
		return err
	}
	c.remoteDescription = sess

	return nil
}

func (c *StandardMediaTransport) CreateAnswer() (*Desc, error) {
	return &Desc{
		Type: "offer",
		SDP:  c.localDescription.String(),
	}, nil
}

func (c *StandardMediaTransport) RequestKeyFrame() error {
	if c.videoSSRC == 0 {
		return fmt.Errorf("video ssrc is 0")
	}
	return c.sendPLI(c.videoSSRC)
}

func (c *StandardMediaTransport) sendPLI(ssrc uint32) error {
	pli := rtcp.PictureLossIndication{MediaSSRC: uint32(ssrc)}

	_, errSend := c.WriteRTCP(TrackTypeVideo, &pli)
	if errSend != nil {
		logger.Error(errSend)
		return errSend
	}
	logger.Infof("Sent PLI %v", pli)
	return nil
}

func (c *StandardMediaTransport) sendTntervalPlic(ssrc uint32) error {
	go func() {
		ticker := time.NewTicker(time.Second * 1)
		for range ticker.C {
			if c.closed.Get() {
				logger.Infof("Terminate: stop pli loop now!")
				return
			}
			pli := rtcp.PictureLossIndication{SenderSSRC: uint32(0), MediaSSRC: uint32(ssrc)}
			_, errSend := c.WriteRTCP(TrackTypeVideo, &pli)
			if errSend != nil {
				logger.Error(errSend)
				return
			}
			logger.Infof("Sent PLI %v", pli)
		}
	}()
	return nil
}

func (c *StandardMediaTransport) handleRtcpFeedback(packet []byte) {
	pkts, err := rtcp.Unmarshal(packet)
	if err != nil {
		logger.Errorf("Unmarshal rtcp receiver packets err %v", err)
	}
	var fwdPkts []rtcp.Packet
	pliOnce := true
	firOnce := true
	var (
		maxRatePacketLoss  uint8
		expectedMinBitrate uint64
	)
	for _, pkt := range pkts {
		switch p := pkt.(type) {
		case *rtcp.PictureLossIndication:
			if pliOnce {
				fwdPkts = append(fwdPkts, p)
				logger.Infof("Picture Loss Indication")
				if c.requestKeyFrameHandler != nil {
					c.requestKeyFrameHandler()
				}
				pliOnce = false
			}
		case *rtcp.FullIntraRequest:
			if firOnce {
				fwdPkts = append(fwdPkts, p)
				logger.Infof("FullIntraRequest")
				if c.requestKeyFrameHandler != nil {
					c.requestKeyFrameHandler()
				}
				firOnce = false
			}
		case *rtcp.ReceiverEstimatedMaximumBitrate:
			if expectedMinBitrate == 0 || expectedMinBitrate > uint64(p.Bitrate) {
				expectedMinBitrate = uint64(p.Bitrate)
				logger.Debugf(" ReceiverEstimatedMaximumBitrate %d", expectedMinBitrate/1024)
			}
		case *rtcp.ReceiverReport:
			for _, r := range p.Reports {
				if maxRatePacketLoss == 0 || maxRatePacketLoss < r.FractionLost {
					maxRatePacketLoss = r.FractionLost
					logger.Infof("maxRatePacketLoss %d", maxRatePacketLoss)
				}
			}
		case *rtcp.TransportLayerNack:
			logger.Infof("Nack %v", p)
		}
	}
}
