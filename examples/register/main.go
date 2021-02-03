package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/media/rtp"
	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip/parser"
)

var (
	logger log.Logger
	udp    *rtp.RtpUDPStream
)

func init() {
	logger = log.NewDefaultLogrusLogger().WithPrefix("Client")
}

func main() {

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	stack := stack.NewSipStack(&stack.SipStackConfig{Extensions: []string{"replaces", "outbound"}, Dns: "8.8.8.8"}, logger)

	if err := stack.Listen("udp", "0.0.0.0:5066"); err != nil {
		logger.Panic(err)
	}

	ua := ua.NewUserAgent(&ua.UserAgentConfig{
		UserAgent: "Go Sip Client/1.0.0",
		SipStack:  stack,
	}, logger)

	ua.RegisterStateHandler = func(state account.RegisterState) {
		logger.Infof("RegisterStateHandler: user => %s, state => %v, expires => %v, reason => %v", state.Account.AuthInfo.AuthUser, state.StatusCode, state.Expiration, state.Reason)
	}

	uri, err := parser.ParseUri("sip:100@127.0.0.1:5060")
	if err != nil {
		logger.Error(err)
	}

	profile := account.NewProfile(uri.Clone(), "goSIP",
		&account.AuthInfo{
			AuthUser: "100",
			Password: "100",
			Realm:    "b2bua",
		},
		1800,
	)

	recipient, err := parser.ParseSipUri("sip:127.0.0.1:5060;transport=udp")
	if err != nil {
		logger.Error(err)
	}

	go ua.SendRegister(profile, recipient, profile.Expires)

	<-stop

	ua.Shutdown()
}
