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
	udpConns                 []*net.UDPConn
	closed                   utils.AtomicBool
	ctx                      context.Context
	cancel                   context.CancelFunc
	onRtpPacketReceivedFunc  func(packet []byte, raddr net.Addr)
	onRtcpPacketReceivedFunc func(packet []byte, raddr net.Addr)
	mutex                    sync.Mutex
	trackType                TrackType
	externalRtpAddress       string
	rAddr                    *net.Addr
	rRtcpAddr                *net.Addr
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

	rtpConns, err := ListenRTPInPortRange(3000, 5000, "udp", lAddr, lRtcpAddr)
	if err != nil {
		logger.Errorf("ListenUDP: err => %v", err)
		return err
	}

	logger.Infof("ListenUDP: rtp %v, rtcp ", rtpConns[0].LocalAddr().String(), rtpConns[1].LocalAddr().String())

	go c.loop(rtpConns[0], func(packet []byte, raddr net.Addr) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		if c.onRtpPacketReceivedFunc != nil {
			c.onRtpPacketReceivedFunc(packet, raddr)
		}
		c.rAddr = &raddr
	})

	go c.loop(rtpConns[1], func(packet []byte, raddr net.Addr) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		if c.onRtcpPacketReceivedFunc != nil {
			c.onRtcpPacketReceivedFunc(packet, raddr)
		}
		c.rRtcpAddr = &raddr
	})

	c.udpConns = rtpConns
	return nil
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

func (c *UdpPort) OnRtpPacketReceived(callback func(packet []byte, raddr net.Addr)) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.onRtpPacketReceivedFunc = callback
}

func (c *UdpPort) OnRtcpPacketReceived(callback func(packet []byte, raddr net.Addr)) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.onRtcpPacketReceivedFunc = callback
}

func (c *UdpPort) WriteRtpPacket(data []byte, raddr net.Addr) error {
	if c.closed.Get() {
		return fmt.Errorf("closed")
	}
	if c.udpConns != nil {
		_, err := c.udpConns[0].WriteToUDP(data, raddr.(*net.UDPAddr))
		return err
	}
	return nil
}

func (c *UdpPort) WriteRtcpPacket(data []byte, raddr net.Addr) error {
	if c.closed.Get() {
		return fmt.Errorf("closed")
	}
	if c.udpConns != nil {
		_, err := c.udpConns[1].WriteToUDP(data, raddr.(*net.UDPAddr))
		return err
	}
	return nil
}

func (c *UdpPort) loop(conn *net.UDPConn, onPacketReceived func(data []byte, raddr net.Addr)) {
	buf := make([]byte, 1500)
	for {
		if c.closed.Get() {
			logger.Infof("Terminate: stop rtp conn now!")
			return
		}
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			logger.Infof("RTP Conn [%v] refused, stop now!", raddr)
			return
		}
		logger.Debugf("raddr: %v, size %d", raddr, n)
		onPacketReceived(buf[:n], raddr)
	}
}
