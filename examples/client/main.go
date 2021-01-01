package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewDefaultLogrusLogger().WithPrefix("Client")
}

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	stack := stack.NewSipStack(&stack.SipStackConfig{Extensions: []string{"replaces", "outbound"}, Dns: "8.8.8.8"}, logger)

	listen := "0.0.0.0:5080"
	logger.Infof("Listen => %s", listen)

	if err := stack.Listen("udp", listen, nil); err != nil {
		logger.Panic(err)
	}

	if err := stack.Listen("tcp", listen, nil); err != nil {
		logger.Panic(err)
	}

	ua := ua.NewUserAgent(&ua.UserAgentConfig{
		UserAgent: "Go Sip Client/1.0.0",
		SipStack:  stack,
	}, logger)

	ua.InviteStateHandler = func(sess *session.Session, req *sip.Request, resp *sip.Response, state session.Status) {
		logger.Infof("InviteStateHandler: state => %v, type => %s", state, sess.Direction())
		if state == session.InviteReceived {
			sess.ProvideAnswer("")
			sess.Accept(200)
		}
	}

	ua.RegisterStateHandler = func(state account.RegisterState) {
		logger.Infof("RegisterStateHandler: user => %s, state => %v, expires => %v", state.Account.Auth.AuthName, state.StatusCode, state.Expiration)
	}

	profile := account.NewProfile("100", "goSIP",
		&account.AuthInfo{
			AuthName: "100",
			Password: "100",
			Realm:    "",
		},
		1800,
	)

	target, err := parser.ParseSipUri("sip:100@127.0.0.1:5060;transport=udp")
	if err != nil {
		logger.Error(err)
	}

	go ua.SendRegister(profile, target, profile.Expires)
	time.Sleep(time.Second * 10)
	go ua.SendRegister(profile, target, 0)
	/*
		sdp := mock.answer.String()
		called := "weiweiduan"
		go ua.Invite(profile, &sip.SipUri{
			FUser:      sip.String{Str: called},
			FHost:      target.Host(),
			FPort:      target.Port(),
			FUriParams: target.UriParams(),
		}, &sdp)
	*/
	<-stop

	ua.Shutdown()
}
