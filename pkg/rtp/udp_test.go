package rtp_test

import (
	"sync"
	"testing"

	"github.com/cloudwebrtc/go-sip-ua/pkg/rtp"
	"github.com/ghettovoice/gosip/log"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var (
	logger *log.LogrusLogger
	wg     = new(sync.WaitGroup)
)

func init() {
	logrusNew := logrus.New()
	logrusNew.Formatter = &prefixed.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05.000",
		ForceColors:     true,
		ForceFormatting: true,
	}
	logrusNew.SetLevel(logrus.DebugLevel)
	logger = log.NewLogrusLogger(logrusNew, "rtp_test", nil)
}

func TestUdpStream(t *testing.T) {
	udp := rtp.NewRtpUDPStream("127.0.0.1", rtp.DefaultPortMin, rtp.DefaultPortMax, func(data []byte) {
		wg.Done()

		got := string(data)
		if got != "hello" {
			t.Errorf("onpkt = %s; want hello", got)
		}

		logger.Debugf("onpkt %v\n", got)
	}, logger)

	logger.Debugf("laddr %v\n", udp.LocalAddr())

	wg.Add(1)
	go udp.Read()

	n, err := udp.Send([]byte("hello"), udp.LocalAddr())

	if err != nil {
		t.Error(err)
	}

	if n != 5 {
		t.Errorf("Send = %d; want 5", n)
	}

	logger.Infof("Send res %v", n)
	wg.Wait()
	udp.Close()
}
