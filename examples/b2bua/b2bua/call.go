package b2bua

type CallType string

const (
	SIP CallType = "SIP"
	RTC CallType = "WebRTC"
)

type CallStatus string

const (
	Connecting CallStatus = "Connecting"
	Ringing    CallStatus = "Ringing"
	EarlyMedia CallStatus = "EarlyMedia"
	Confirmed  CallStatus = "Confirmed"
	Failure    CallStatus = "Failure"
	Terminated CallStatus = "Terminated"
)

// Call interface.
type Call interface {
	Init()
	Terminate()
	ChannelID() int
	Offer() (*Desc, error)
	OnEarlyMedia(desc *Desc) error
	OnAnswer(desc *Desc) error
	OnOffer(sdp *Desc) error
	Answer() (*Desc, error)
	Called() string
	Type() CallType
	ID() string
	Status() chan CallStatus
}

type Desc struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}
