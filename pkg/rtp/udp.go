package udp

import (
	"net"

	"github.com/cloudwebrtc/go-sip-ua/pkg/logger"
	"github.com/cloudwebrtc/go-sip-ua/pkg/util"
)

const (
	DefaultPortStart = 30000
	DefaultPortEnd   = 65530
)

type RtpUDPStream struct {
	conn     *net.UDPConn
	stop     bool
	onPacket func(pkt []byte)
	laddr    *net.UDPAddr
	raddr    *net.UDPAddr
}

func NewRtpUDPStream(PortRangeMin, PortRangeMax int, callback func(pkt []byte)) *RtpUDPStream {
	lAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	var err error
	conn, err := util.ListenUDPInPortRange(PortRangeMin, PortRangeMax, lAddr)
	if err != nil {
		logger.Errorf("ListenUDP: err => %v", err)
		return nil
	}
	return &RtpUDPStream{
		conn:     conn,
		stop:     false,
		onPacket: callback,
		laddr:    lAddr,
	}
}

func (r *RtpUDPStream) RemoteAddr() *net.UDPAddr {
	return r.raddr
}

func (r *RtpUDPStream) LocalAddr() *net.UDPAddr {
	return r.laddr
}

func (r *RtpUDPStream) Close() {
	r.stop = true
	r.conn.Close()
}

func (r *RtpUDPStream) Send(pkt []byte, raddr *net.UDPAddr) (int, error) {
	r.raddr = raddr
	return r.conn.WriteToUDP(pkt, raddr)
}

func (r *RtpUDPStream) Read() {
	buf := make([]byte, 1500)
	for {
		if r.stop {
			logger.Infof("Terminate: stop rtp conn now!")
			return
		}
		n, raddr, err := r.conn.ReadFrom(buf)
		if err != nil {
			logger.Infof("RTP Conn [%v] refused, stop now!", raddr)
			return
		}

		logger.Debugf("Read rtp from: %v, length: %d", raddr.String(), n)

		if !r.stop {
			r.onPacket(buf[0:n])
		}
	}
}
