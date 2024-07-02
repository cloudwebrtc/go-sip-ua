package b2bua

type BridgeType string

const (
	B2BCall       BridgeType = "B2BCall"
	OriginateCall BridgeType = "OriginateCall"
	Conference    BridgeType = "Conference"
)

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

func (b *CallBridge) ToString() string {
	return b.src.ToString() + " -> " + b.dest.ToString()
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
