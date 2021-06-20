package media

//Media interface
type Media interface {
	CreateOffer() (*Description, error)
	CreateAnswer() (*Description, error)
	SetLocalDescription(desc *Description) error
	SetRemoteDescription(desc *Description) error
	Tracks() map[string]*Track
	OnTrack(func(*Track))
}

//Description sdp
type Description struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}
