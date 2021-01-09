package media

//Media interface
type Media interface {
	CreateOffer() (*Description, error)
	CreateAnswer() (*Description, error)
	SetLocalDescription(desc *Description) error
	SetRemoteDescription(desc *Description) error
}

//Description sdp
type Description struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}
