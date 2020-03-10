package media

import (
	"net"

	"github.com/cloudwebrtc/go-sip-ua/pkg/rtp/udp"
	"github.com/ghettovoice/gosip/log"
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewDefaultLogrusLogger().WithPrefix("MediaSession")
}

const (
	maxRtpConnSize = 1024
)

// UDPTransport .
type UDPTransport struct {
	listener *udp.Listener
	stop     bool
}

// NewSession .
func NewUDPTransport() *UDPTransport {
	s := &UDPTransport{
		stop: false,
	}
	return s
}

// Serve listen on a port and accept udp conn
func (s *UDPTransport) Serve(port int) (chan *udp.Conn, error) {
	logger.Infof("rtpengine.Serve port=%d ", port)
	if s.listener != nil {
		s.listener.Close()
	}
	ch := make(chan *udp.Conn, maxRtpConnSize)
	var err error
	s.listener, err = udp.Listen("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		logger.Errorf("failed to listen %v", err)
		return nil, err
	}

	go func() {
		for {
			if s.stop {
				return
			}
			conn, err := s.listener.Accept()
			if err != nil {
				logger.Errorf("failed to accept conn %v", err)
				continue
			}
			logger.Infof("accept new rtp conn %s", conn.RemoteAddr().String())

			ch <- conn
		}
	}()
	return ch, nil
}
