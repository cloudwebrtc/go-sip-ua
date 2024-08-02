package b2bua

import "github.com/pion/webrtc/v3"

type UserAgentMediaConfig struct {
	Codecs             []string              `json:"codecs"`
	ExternalRtpAddress string                `json:"external_rtp_address"`
	RtcpFeedback       []webrtc.RTCPFeedback `json:"rtcp_feedback"`
}
