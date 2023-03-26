package b2bua

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
	"github.com/pixelbender/go-sdp/sdp"
)

// SIPCall .
type SIPCall struct {
	ua             *ua.UserAgent
	sess           *session.Session
	profile        *account.Profile
	dir            session.Direction
	localSdp       *sdp.Session
	remoteSdp      *sdp.Session
	udpConn        *net.UDPConn
	closed         utils.AtomicBool
	called         sip.SipUri
	currentStatus  CallStatus
	ch             chan CallStatus
	id             string
	hasMediaStream utils.AtomicBool
	ctx            context.Context
	cancel         context.CancelFunc
	mutex          sync.Mutex
}

func NewSIPCall(ua *ua.UserAgent, sess *session.Session, profile *account.Profile, dir session.Direction, cid string) *SIPCall {
	c := &SIPCall{
		ua:      ua,
		sess:    sess,
		profile: profile,
		dir:     dir,
		ch:      make(chan CallStatus, 1),
		id:      cid,
	}
	c.ctx, c.cancel = context.WithCancel(context.TODO())
	c.closed.Set(false)
	c.hasMediaStream.Set(false)

	return c
}

func (c *SIPCall) Init(ExternalIP string) error {
	lAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	var err error
	c.udpConn, err = ListenUDPInPortRange(3000, 5000, "udp", lAddr)
	if err != nil {
		logger.Errorf("ListenUDP: err => %v", err)
		return err
	}
	host := "127.0.0.1"
	if v, err := ResolveSelfIP(); err == nil {
		host = v.String()
	}

	if len(ExternalIP) > 0 {
		host = ExternalIP
	}

	c.localSdp = &sdp.Session{
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
		Media: []*sdp.Media{
			{
				//Bandwidth: []*sdp.Bandwidth{{Type: "TIAS", Value: 96000}},
				Connection: []*sdp.Connection{{Address: host}},
				Mode:       sdp.SendRecv,
				Type:       "audio",
				Port:       lAddr.Port,
				Proto:      "RTP/AVP",
				Format: []*sdp.Format{
					{Payload: 0, Name: "PCMU", ClockRate: 8000},
					{Payload: 8, Name: "PCMA", ClockRate: 8000},
					//{Payload: 18, Name: "G729", ClockRate: 8000, Params: []string{"annexb=yes"}},
					{Payload: 116, Name: "telephone-event", ClockRate: 8000, Params: []string{"0-16"}},
				},
			},
		},
	}
	logger.Warnf("SIPCall.Init")
	return nil
}

func (c *SIPCall) OnFailure(code int, reason string) {
	if !c.sess.IsEnded() {
		c.sess.End()
	}
	c.ch <- Failure
	logger.Warnf("SIPCall.Failure")
}

func (c *SIPCall) OnTerminate() {
	{
		c.mutex.Lock()
		defer c.mutex.Unlock()

		if !c.closed.Get() {
			c.closed.Set(true)
		}

		if c.udpConn != nil {
			c.udpConn.Close()
			c.udpConn = nil
		}
	}
	c.ch <- Terminated
}

func (c *SIPCall) Terminate() {
	{
		c.mutex.Lock()
		defer c.mutex.Unlock()
		//TODO: close udp conn

		if !c.closed.Get() {
			c.closed.Set(true)
		}
		if c.udpConn != nil {
			c.udpConn.Close()
			c.udpConn = nil
		}
	}

	if !c.sess.IsEnded() {
		c.sess.End()
	}
	c.cancel()
	logger.Warnf("SIPCall.Terminate")
}

func (c *SIPCall) Close() {
	c.Terminate()
	logger.Warnf("SIPCall.Close")
}

func (c *SIPCall) Offer(called sip.SipUri) (string, error) {
	c.called = called
	sdp := c.localSdp.String()
	recipient := sip.SipUri{
		FUser: sip.String{Str: c.called.User().String()},
		FHost: c.called.Host(),
		FPort: c.called.Port(),
	}

	uri, err := parser.ParseUri("sip:" + c.called.User().String() + "@" + c.called.Host())
	if err != nil {
		logger.Error(err)
		return "", err
	}

	logger.Infof("SIPCall Invite => %v", sdp)

	sess, err := c.ua.Invite(c.profile, uri, recipient, &sdp)
	if err != nil {
		return "", err
	}
	c.sess = sess

	return sdp, nil
}

func (c *SIPCall) OnEarlyMedia(answer string) error {
	var err error
	c.remoteSdp, err = sdp.Parse([]byte(answer))
	if err != nil {
		logger.Errorf("err => %v", err)
	}

	c.currentStatus = EarlyMedia
	c.ch <- c.currentStatus

	rAddr := &net.UDPAddr{IP: net.ParseIP(c.remoteSdp.Origin.Address), Port: c.remoteSdp.Media[0].Port}

	if !c.hasMediaStream.Get() {
		c.hasMediaStream.Set(true)
		go c.startStreamLoop(rAddr)
	}

	return err
}

func (c *SIPCall) OnAnswer(answer string) error {

	logger.Infof("SIPCall onAnswer => %v", answer)

	var err error
	c.remoteSdp, err = sdp.Parse([]byte(answer))
	if err != nil {
		logger.Errorf("err => %v", err)
	}

	rAddr := &net.UDPAddr{IP: net.ParseIP(c.remoteSdp.Origin.Address), Port: c.remoteSdp.Media[0].Port}

	if !c.hasMediaStream.Get() {
		c.hasMediaStream.Set(true)
		go c.startStreamLoop(rAddr)
	}

	if c.currentStatus != Confirmed {
		c.currentStatus = Confirmed
		c.ch <- c.currentStatus
	}
	return err
}

func (c *SIPCall) OnOffer(offer string) error {
	var err error
	logger.Warnf("offer %v", offer)
	c.remoteSdp, err = sdp.Parse([]byte(offer))
	if err != nil {
		logger.Errorf("err => %v", err)
	}
	return nil
}

func (c *SIPCall) Answer() (string, error) {

	rAddr := &net.UDPAddr{IP: net.ParseIP(c.remoteSdp.Origin.Address), Port: c.remoteSdp.Media[0].Port}

	c.localSdp.Media[0].Format = c.remoteSdp.Media[0].Format
	sdp := c.localSdp.String()
	logger.Warnf("answer %v", sdp)
	c.sess.ProvideAnswer(sdp)
	c.sess.Accept(sip.StatusCode(200))

	if !c.hasMediaStream.Get() {
		c.hasMediaStream.Set(true)
		go c.startStreamLoop(rAddr)
	}

	if c.currentStatus != Confirmed {
		c.currentStatus = Confirmed
		c.ch <- c.currentStatus
	}
	return "", nil
}

func (c *SIPCall) startStreamLoop(rAddr *net.UDPAddr) {
	logger.Warnf("SIPCall::startStream, Read rtp from: %v", rAddr.String())

	/*
		write rtp/rtcp to udp transport.
			rtpTransport := media.NewGoRtpTransport(func(buffer string) int {
				size := len(buffer)
				if c.udpConn != nil {
					c.udpConn.WriteToUDP([]byte(buffer), rAddr)
				}

				return size
			}, func(buffer string) int {
				size := len(buffer)
				if c.udpConn != nil {
					c.udpConn.WriteToUDP([]byte(buffer), rAddr)
				}
				return size
			})
	*/

	buf := make([]byte, 1500)
	for {
		if c.closed.Get() {
			logger.Infof("Terminate: stop rtp conn now!")
			return
		}
		_, raddr, err := c.udpConn.ReadFrom(buf)
		if err != nil {
			logger.Infof("RTP Conn [%v] refused, stop now!", raddr)
			return
		}
		//logger.Debugf("raddr: %v, size %d", raddr, n)
		if !c.closed.Get() {
			//c.stream.OnReadRtpPacket(string(buf[:n]))
		}
	}
}

func (c *SIPCall) Called() string {
	return c.called.User().String()
}

func (c *SIPCall) Host() string {
	return c.called.Host()
}

func (c *SIPCall) Type() CallType {
	return SIP
}

func (c *SIPCall) ID() string {
	return c.id
}

func (c *SIPCall) Sess() *session.Session {
	return c.sess
}

func (c *SIPCall) StatusChan() chan CallStatus {
	return c.ch
}
