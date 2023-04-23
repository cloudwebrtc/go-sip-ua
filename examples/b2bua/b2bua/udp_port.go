package b2bua

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
)

// UdpPort .
type UdpPort struct {
	udpConns             []*net.UDPConn
	closed               utils.AtomicBool
	ctx                  context.Context
	cancel               context.CancelFunc
	onRtpPacketCallback  func(trackType TrackType, packet []byte, raddr net.Addr) error
	onRtcpPacketCallback func(trackType TrackType, packet []byte, raddr net.Addr) error
	mutex                sync.Mutex
	trackType            TrackType
	externalRtpAddress   string
	rAddr                *net.Addr
	rRtcpAddr            *net.Addr
}

func NewUdpPort(trackType TrackType, externalRtpAddress string) (*UdpPort, error) {
	c := &UdpPort{
		trackType:          trackType,
		externalRtpAddress: externalRtpAddress,
	}
	c.ctx, c.cancel = context.WithCancel(context.TODO())
	c.closed.Set(false)
	return c, nil
}

func (c *UdpPort) Init() error {
	lAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	lRtcpAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}

	rtpConns, err := ListenRTPInPortRange(4000, 5000, "udp", lAddr, lRtcpAddr)
	if err != nil {
		logger.Errorf("ListenUDP: err => %v", err)
		return err
	}

	logger.Infof("ListenUDP: rtp %v, rtcp ", rtpConns[0].LocalAddr().String(), rtpConns[1].LocalAddr().String())

	go c.loop(rtpConns[0], func(packet []byte, raddr net.Addr) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		c.rAddr = &raddr
		if c.onRtpPacketCallback != nil {
			c.onRtpPacketCallback(c.trackType, packet, raddr)
		}
	})

	go c.loop(rtpConns[1], func(packet []byte, raddr net.Addr) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		c.rRtcpAddr = &raddr
		if c.onRtcpPacketCallback != nil {
			c.onRtcpPacketCallback(c.trackType, packet, raddr)
		}
	})

	c.udpConns = rtpConns
	return nil
}

func (c *UdpPort) GetTrackType() TrackType {
	return c.trackType
}

func (c *UdpPort) LocalPort() int {
	return c.udpConns[0].LocalAddr().(*net.UDPAddr).Port
}

func (c *UdpPort) GetRemoteRtpAddress() *net.Addr {
	return c.rAddr
}

func (c *UdpPort) GetRemoteRtcpAddress() *net.Addr {
	if c.rRtcpAddr == nil {
		return c.rAddr
	}
	return c.rRtcpAddr
}

func (c *UdpPort) Close() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.closed.Get() {
		c.closed.Set(true)
	}
	c.cancel()

	for _, conn := range c.udpConns {
		conn.Close()
	}
	c.udpConns = nil

}

func (c *UdpPort) OnRtpPacketReceived(callback func(trackType TrackType, packet []byte, raddr net.Addr) error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.onRtpPacketCallback = callback
}

func (c *UdpPort) OnRtcpPacketReceived(callback func(trackType TrackType, packet []byte, raddr net.Addr) error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.onRtcpPacketCallback = callback
}

func (c *UdpPort) WriteRtpPacket(data []byte, raddr net.Addr) (int, error) {
	if c.closed.Get() {
		return 0, fmt.Errorf("closed")
	}
	if c.udpConns != nil {
		return c.udpConns[0].WriteToUDP(data, raddr.(*net.UDPAddr))
	}
	return 0, fmt.Errorf("udpConns is nil")
}

func (c *UdpPort) WriteRtcpPacket(data []byte, raddr net.Addr) (int, error) {
	if c.closed.Get() {
		return 0, fmt.Errorf("closed")
	}
	if c.udpConns != nil {
		return c.udpConns[1].WriteToUDP(data, raddr.(*net.UDPAddr))
	}
	return 0, fmt.Errorf("udpConns is nil")
}

func (c *UdpPort) loop(conn *net.UDPConn, onPacketReceived func(data []byte, raddr net.Addr)) {
	buf := make([]byte, 1500)
	for {
		if c.closed.Get() {
			logger.Infof("Terminate: stop rtp conn now!")
			return
		}
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Infof("RTP Conn [%v] refused, stop now!", raddr)
			return
		}
		//logger.Infof("raddr: %v, size %d", raddr, n)
		onPacketReceived(buf[:n], raddr)
	}
}
