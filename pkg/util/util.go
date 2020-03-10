package util

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

func GetIP(addr string) string {
	if strings.Contains(addr, ":") {
		return strings.Split(addr, ":")[0]
	}
	return ""
}

func GetPort(addr string) string {
	if strings.Contains(addr, ":") {
		return strings.Split(addr, ":")[1]
	}
	return ""
}

func StrToUint16(str string) uint16 {
	i, _ := strconv.ParseUint(str, 10, 16)
	return uint16(i)
}

func BuildContactHeader(name string, from, to sip.Message, expires *sip.Expires) {
	name = strings.ToLower(name)
	for _, h := range from.GetHeaders(name) {
		AddParamsToContact(h.(*sip.ContactHeader), expires)
		to.AppendHeader(h.Clone())
	}
}

func AddParamsToContact(contact *sip.ContactHeader, expires *sip.Expires) {
	if urn, ok := contact.Params.Get("+sip.instance"); ok {
		contact.Params.Add("+sip.instance", sip.String{Str: fmt.Sprintf(`"%s"`, urn)})
	}
	if expires != nil {
		contact.Params.Add("expires", sip.String{Str: fmt.Sprintf("%d", int(*expires))})
	}
}

func NewLogrusLogger(level logrus.Level) *log.LogrusLogger {
	logger := logrus.New()
	logger.Level = logrus.ErrorLevel
	logger.Formatter = &prefixed.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05.000",
		ForceColors:     true,
		ForceFormatting: true,
	}
	logger.SetLevel(level)
	logger.SetReportCaller(true)
	return log.NewLogrusLogger(logger, "main", nil)
}
