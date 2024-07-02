package rtp

import (
	"net"

	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/log"
)

const (
	DefaultPortMin = 30000
	DefaultPortMax = 65530
)

type RtpUDPStream struct {
	conn     *net.UDPConn
	stop     bool
	onPacket func(pkt []byte, raddr net.Addr)
	laddr    *net.UDPAddr
	raddr    *net.UDPAddr
	logger   log.Logger
}

func NewRtpUDPStream(bind string, portMin, portMax int, callback func(pkt []byte, raddr net.Addr)) *RtpUDPStream {

	logger := utils.NewLogrusLogger(utils.DefaultLogLevel, "Media", nil)

	lAddr := &net.UDPAddr{IP: net.ParseIP(bind), Port: 0}
	var err error
	conn, err := utils.ListenUDPInPortRange(portMin, portMax, lAddr)
	if err != nil {
		logger.Errorf("ListenUDP: err => %v", err)
		return nil
	}

	return &RtpUDPStream{
		conn:     conn,
		stop:     false,
		onPacket: callback,
		laddr:    lAddr,
		logger:   logger,
	}
}

func (r *RtpUDPStream) Log() log.Logger {
	return r.logger
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
	r.Log().Debugf("Send to %v, length %d", raddr.String(), len(pkt))
	r.raddr = raddr
	return r.conn.WriteToUDP(pkt, raddr)
}

func (r *RtpUDPStream) Read() {

	r.Log().Infof("Read")

	buf := make([]byte, 1500)
	for {
		if r.stop {
			r.Log().Infof("Terminate: stop rtp conn now!")
			return
		}
		n, raddr, err := r.conn.ReadFrom(buf)
		if err != nil {
			r.Log().Warnf("RTP Conn [%v] refused, err: %v, stop now!", raddr, err)
			return
		}

		r.Log().Tracef("Read rtp from: %v, length: %d", raddr.String(), n)

		if !r.stop {
			r.onPacket(buf[0:n], raddr)
		}
	}
}
