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

type UdpTansport struct {
	trackInfos        []*TrackInfo
	ports             map[TrackType]*UdpPort
	localDescription  *sdp.Session
	remoteDescription *sdp.Session

	mu                     sync.RWMutex
	rtpHandler             func(trackType TrackType, payload []byte)
	rtcpHandler            func(trackType TrackType, payload []byte)
	requestKeyFrameHandler func()

	videoSSRC uint32
	closed    utils.AtomicBool
	ctx       context.Context
	cancel    context.CancelFunc

	id string
}

func NewUdpTansport(id string, trackInfos []*TrackInfo) *UdpTansport {
	t := &UdpTansport{
		trackInfos: trackInfos,
		ports:      make(map[TrackType]*UdpPort),
		videoSSRC:  0,
		id:         id,
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
		//Name: "play", // Session Name ("s=")
		Connection: &sdp.Connection{
			Address: host,
		},
		//Bandwidth: []*sdp.Bandwidth{{Type: "AS", Value: 117}},
	}

	var medias []*sdp.Media

	for _, trackInfo := range c.trackInfos {

		var rAddr *net.UDPAddr = nil
		var rRtcpAddr *net.UDPAddr = nil
		if trackInfo.Connection != nil {
			rAddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", trackInfo.Connection.Address, trackInfo.Port))
			rRtcpAddr, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", trackInfo.Connection.Address, trackInfo.RtcpPort))
		}

		udpPort, err := NewUdpPort(c.id, trackInfo.TrackType, rAddr, rRtcpAddr, config.ExternalRtpAddress)
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
			//for _, enabledCodec := range callConfig.Codecs {
			//	if codec.Name == enabledCodec {
			formats = append(formats, &sdp.Format{
				Payload:   codec.Payload,
				Name:      codec.Name,
				ClockRate: codec.ClockRate,
				Params:    codec.Params,
				Feedback:  codec.Feedback,
				Channels:  codec.Channels,
			})
			//	}
			//}
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

func (c *UdpTansport) OnRequestKeyFrame(keyHandler func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestKeyFrameHandler = keyHandler
}

func (c *UdpTansport) onRtpPacket(trackType TrackType, packet []byte, raddr net.Addr) error {
	logger.Debugf("UdpTansport::OnRtpPacketReceived: %v read %d bytes, raddr %v", trackType, len(packet), raddr)

	if len(packet) == 8 {
		pkts, err := rtcp.Unmarshal(packet)
		if err != nil {
			logger.Errorf("Unmarshal rtcp receiver packets err %v", err)
		}
		for _, pkt := range pkts {
			logger.Warnf("Unkown packet: %v, pkt %v DestinationSSRC %v", trackType, packet, pkt.DestinationSSRC())
		}
		return nil
	}

	p := &rtp.Packet{}
	if err := p.Unmarshal(packet); err != nil {
		logger.Errorf("rtp.Packet Unmarshal: e %v len %v", err, len(packet))
	}

	logger.Debugf("UdpTansport::onRtpPacket: [%v] read %d bytes, seq %d, ts %d, ssrc %v, payload %v", trackType, len(packet), p.SequenceNumber, p.Timestamp, p.SSRC, p.PayloadType)

	if trackType == TrackTypeVideo && c.videoSSRC == 0 {
		c.videoSSRC = p.SSRC
		//c.sendPLI(c.videoSSRC)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(packet) < 12 {
		if c.rtcpHandler != nil {
			c.rtcpHandler(trackType, packet)
		}
	} else {
		if c.rtpHandler != nil {
			c.rtpHandler(trackType, packet)
		}
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
	/*
		p := &rtp.Packet{}
		if err := p.Unmarshal(packet); err != nil {
			logger.Errorf("tp.Packet Unmarshal: e %v", err)
		}
		logger.Debugf("UdpTansport::WriteRTP: %v, write %d bytes, seq %d, ts %d", trackType, len(packet), p.SequenceNumber, p.Timestamp)

		pktbuf, err := p.Marshal()

		if err != nil {
			logger.Errorf("UdpTansport::WriteRTP: Marshal rtp receiver packets err %v", err)
		}
	*/

	port := c.ports[trackType]

	if port == nil {
		logger.Errorf("UdpTansport::WriteRTP: port is nil")
		return 0, nil
	}

	return port.WriteRtp(packet)
}

func (c *UdpTansport) WriteRTCP(trackType TrackType, packet []byte) (int, error) {
	/*
		pkts, err := rtcp.Unmarshal(packet)
		if err != nil {
			logger.Errorf("UdpTansport::WriteRTP: Unmarshal rtcp receiver packets err %v", err)
		}

		logger.Debugf("UdpTansport::WriteRTCP: %v read %d packets", trackType, len(pkts))
	*/
	port := c.ports[trackType]

	if port == nil {
		logger.Errorf("UdpTansport::WriteRTCP: port is nil")
		return 0, nil
	}
	return port.WriteRtcp(packet)
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
	conn := sess.Connection
	if conn != nil {
		logger.Debugf("remote connection address: %s", conn.Address)
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

func (c *UdpTansport) RequestKeyFrame() error {
	if c.videoSSRC == 0 {
		return fmt.Errorf("video ssrc is 0")
	}
	return c.sendPLI(c.videoSSRC)
}

func (c *UdpTansport) sendPLI(ssrc uint32) error {
	pli := rtcp.PictureLossIndication{MediaSSRC: uint32(ssrc)}
	buf, err := pli.Marshal()
	if err != nil {
		logger.Error(err)
		return err
	}
	_, errSend := c.WriteRTCP(TrackTypeVideo, buf)
	if errSend != nil {
		logger.Error(errSend)
		return err
	}
	logger.Infof("Sent PLI %v", pli)
	return nil
}

func (c *UdpTansport) sendTntervalPlic(ssrc uint32) error {
	go func() {
		ticker := time.NewTicker(time.Second * 1)
		for range ticker.C {
			if c.closed.Get() {
				logger.Infof("Terminate: stop pli loop now!")
				return
			}
			pli := rtcp.PictureLossIndication{SenderSSRC: uint32(0), MediaSSRC: uint32(ssrc)}
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

func (c *UdpTansport) handleRtcpFeedback(packet []byte) {
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
