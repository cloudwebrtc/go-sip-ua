package main

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudwebrtc/go-sip-ua/examples/mock"
	"github.com/cloudwebrtc/go-sip-ua/pkg/media/rtp"
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
)

var (
	logger log.Logger
	udp    *rtp.RtpUDPStream
)

func init() {
	logger = utils.NewLogrusLogger(log.InfoLevel, "Client", nil)
}

func createUdp() *rtp.RtpUDPStream {

	udp = rtp.NewRtpUDPStream("127.0.0.1", rtp.DefaultPortMin, rtp.DefaultPortMax, func(data []byte, raddr net.Addr) {
		logger.Infof("Rtp recevied: %v, laddr %s : raddr %s", len(data), udp.LocalAddr().String(), raddr)
		dest, _ := net.ResolveUDPAddr(raddr.Network(), raddr.String())
		logger.Infof("Echo rtp to %v", raddr)
		udp.Send(data, dest)
	})

	go udp.Read()

	return udp
}

// UDP Server端
func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	stack := stack.NewSipStack(&stack.SipStackConfig{
		UserAgent:  "Go Sip Client/example-client",
		Extensions: []string{"replaces", "outbound"},
		Dns:        "8.8.8.8"})

	listen := "0.0.0.0:5063"
	logger.Infof("Listen => %s", listen)

	if err := stack.Listen("udp", listen); err != nil {
		logger.Panic(err)
	}

	ua := ua.NewUserAgent(&ua.UserAgentConfig{
		SipStack: stack,
	})

	ua.InviteStateHandler = func(sess *session.Session, req *sip.Request, resp *sip.Response, state session.Status) {
		logger.Infof("InviteStateHandler: state => %v, type => %s", state, sess.Direction())

		switch state {
		case session.InviteReceived:
			udp = createUdp()
			udpLaddr := udp.LocalAddr()
			sdp := mock.BuildLocalSdp(udpLaddr.IP.String(), udpLaddr.Port)
			sess.ProvideAnswer(sdp)
			sess.Accept(200)
		case session.Canceled:
			fallthrough
		case session.Failure:
			fallthrough
		case session.Terminated:
			udp.Close()
		}
	}

	<-stop

	ua.Shutdown()
}
