package b2bua

type UserAgentMediaConfig struct {
	Codecs             []string `json:"codecs"`
	ExternalRtpAddress string   `json:"external_rtp_address"`
	RtcpFeedback       []string `json:"rtcp_feedback"`
}
