package b2bua

type CallConfig struct {
	Codecs             []string `json:"codecs"`
	ExternalRtpAddress string   `json:"external_rtp_address"`
}
