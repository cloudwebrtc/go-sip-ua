package b2bua

type BridgeType string

const (
	B2BCall       BridgeType = "B2BCall"
	OriginateCall BridgeType = "OriginateCall"
	Conference    BridgeType = "Conference"
	PlayBack      BridgeType = "PlayBack"
	Record        BridgeType = "Record"
)

func (b BridgeType) String() string {
	return string(b)
}

type CallBridge struct {
	src   *Call
	dest  *Call
	state CallState
	bType BridgeType
}

func (b *CallBridge) Init() {
	b.state = New
}

func (b *CallBridge) State() CallState {
	return b.state
}

func (b *CallBridge) SetState(state CallState) {
	b.state = state
}

func (b *CallBridge) Src() *Call {
	return b.src
}

func (b *CallBridge) Dest() *Call {
	return b.dest
}

func (b *CallBridge) Type() BridgeType {
	return b.bType
}

func (b *CallBridge) ToString() string {
	str := b.Type().String() + ": [" + b.src.ToString() + " -> " + b.dest.ToString() + "]\n"
	str = str + "State: " + b.State().String() + "\n"
	str = str + "Src: " + b.src.MediaInfo() + "\n"
	str = str + "Dest: " + b.dest.MediaInfo()
	return str
}

func (b *CallBridge) Terminate(call *Call) {
	if b.bType == B2BCall || b.bType == OriginateCall {
		if b.src == call {
			b.dest.Terminate()
		} else if b.dest == call {
			b.src.Terminate()
		}
		b.state = Terminated
	}
}

func BridgeMediaStream(src, dest MediaTransport) error {
	src.OnRtpPacket(dest.WriteRTP)
	src.OnRtcpPacket(dest.WriteRTCP)
	src.OnRequestKeyFrame(dest.RequestKeyFrame)
	dest.OnRtpPacket(src.WriteRTP)
	dest.OnRtcpPacket(src.WriteRTCP)
	dest.OnRequestKeyFrame(src.RequestKeyFrame)
	return nil
}
