package b2bua

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/util"
)

type UdpPort struct {
	udpConns           []*net.UDPConn
	closed             utils.AtomicBool
	ctx                context.Context
	cancel             context.CancelFunc
	handleRtpPacket    func(trackType TrackType, packet []byte, raddr net.Addr) error
	handleRtcpPacket   func(trackType TrackType, packet []byte, raddr net.Addr) error
	mutex              sync.Mutex
	trackType          TrackType
	externalRtpAddress string
	rAddr              *net.UDPAddr
	rRtcpAddr          *net.UDPAddr
}

func NewUdpPort(trackType TrackType, rAddr, rRtcpAddr *net.UDPAddr, externalRtpAddress string) (*UdpPort, error) {
	c := &UdpPort{
		trackType:          trackType,
		externalRtpAddress: externalRtpAddress,
		rAddr:              rAddr,
		rRtcpAddr:          rRtcpAddr,
	}
	c.ctx, c.cancel = context.WithCancel(context.TODO())
	c.closed.Set(false)
	return c, nil
}

func (c *UdpPort) Init() error {
	lAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	lRtcpAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}

	// TODO: set port range from config
	rtpConns, err := ListenRTPInPortRange(4000, 5000, "udp", lAddr, lRtcpAddr)
	if err != nil {
		logger.Errorf("ListenUDP: err => %v", err)
		return err
	}

	host := callConfig.ExternalRtpAddress
	if host == "" || host == "0.0.0.0" {
		if v, err := util.ResolveSelfIP(); err == nil {
			host = v.String()
		}
	}

	logger.Infof("[%s] ListenUDP: udp://%s:%v, udp://%s:%v", c.trackType, host, rtpConns[0].LocalAddr().(*net.UDPAddr).Port, host, rtpConns[1].LocalAddr().(*net.UDPAddr).Port)

	go c.loop(rtpConns[0], func(packet []byte, raddr net.Addr) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		c.rAddr = raddr.(*net.UDPAddr)
		if c.handleRtpPacket != nil {
			c.handleRtpPacket(c.trackType, packet, raddr)
		}
	})

	go c.loop(rtpConns[1], func(packet []byte, raddr net.Addr) {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		c.rRtcpAddr = raddr.(*net.UDPAddr)
		if c.handleRtcpPacket != nil {
			c.handleRtcpPacket(c.trackType, packet, raddr)
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

func (c *UdpPort) SetRemoteAddress(raddr *net.UDPAddr) {
	c.rAddr = raddr
}

func (c *UdpPort) SetRemoteRtcpAddress(raddr *net.UDPAddr) {
	c.rRtcpAddr = raddr
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

func (c *UdpPort) OnRtpPacket(callback func(trackType TrackType, packet []byte, raddr net.Addr) error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.handleRtpPacket = callback
}

func (c *UdpPort) OnRtcpPacket(callback func(trackType TrackType, packet []byte, raddr net.Addr) error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.handleRtcpPacket = callback
}

func (c *UdpPort) WriteRtp(data []byte) (int, error) {
	if c.closed.Get() {
		return 0, fmt.Errorf("closed")
	}

	if c.rAddr == nil {
		return 0, fmt.Errorf("rAddr is nil")
	}

	if c.udpConns == nil {
		return 0, fmt.Errorf("udpConns is nil")
	}

	logger.Debugf("UdpPort::WriteRTP: raddr %v", c.rAddr)
	return c.udpConns[0].WriteToUDP(data, c.rAddr)
}

func (c *UdpPort) WriteRtcp(data []byte) (int, error) {
	if c.closed.Get() {
		return 0, fmt.Errorf("closed")
	}
	var addr *net.UDPAddr = c.rRtcpAddr

	if addr == nil {
		addr = c.rRtcpAddr
		if addr == nil {
			return 0, fmt.Errorf("rRtcpAddr is nil")
		}
	}

	if c.udpConns == nil {
		return 0, fmt.Errorf("udpConns is nil")
	}

	logger.Debugf("UdpPort::WriteRTCP: %d packets, raddr %v", len(data), addr)
	return c.udpConns[1].WriteToUDP(data, addr)
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
			logger.Debugf("RTP Conn [%v] refused, stop now!", raddr)
			return
		}
		//logger.Infof("raddr: %v, size %d", raddr, n)
		onPacketReceived(buf[:n], raddr)
	}
}
