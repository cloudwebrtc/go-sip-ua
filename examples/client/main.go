package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"
	"fmt"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/endpoint"
	"github.com/cloudwebrtc/go-sip-ua/pkg/invite"
	"github.com/cloudwebrtc/go-sip-ua/pkg/mock"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
)

const (
	username = "100"
	password = "100"
	displayName = "goSIP"
	sipServer = "127.0.0.1"
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
	endpoint := endpoint.NewEndPoint(&endpoint.EndPointConfig{Extensions: []string{"replaces", "outbound"}, Dns: "8.8.8.8"}, logger)

	listen := "0.0.0.0:5080"
	logger.Infof("Listen => %s", listen)

	if err := endpoint.Listen("udp", listen); err != nil {
		logger.Panic(err)
	}

	if err := endpoint.Listen("tcp", listen); err != nil {
		logger.Panic(err)
	}

	ua := ua.NewUserAgent(&ua.UserAgentConfig{
		UserAgent: "Go Sip Client/1.0.0",
		Endpoint:  endpoint,
	}, logger)

	ua.InviteStateHandler = func(sess *invite.Session, req *sip.Request, resp *sip.Response, state invite.Status) {
		logger.Infof("InviteStateHandler: state => %v, type => %s", state, sess.Direction())
		if state == invite.InviteReceived {
			sess.ProvideAnswer(mock.Answer)
			sess.Accept(200)
		}
	}

	ua.RegisterStateHandler = func(state account.RegisterState) {
		logger.Infof("RegisterStateHandler: user => %s, state => %v, expires => %v", state.Account.Auth.AuthName, state.StatusCode, state.Expiration)
	}

	profile := account.NewProfile(username, displayName,
		&account.AuthInfo{
			AuthName: username,
			Password: password,
			Realm:    "",
		},
		1800,
	)

	uri := fmt.Sprintf("sip:%s@%s:5060;transport=udp", username, sipServer)
	target, err := parser.ParseSipUri(uri)
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
