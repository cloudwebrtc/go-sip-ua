package b2bua

import (
	"fmt"

	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/registry"
	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/session"
	"github.com/cloudwebrtc/go-sip-ua/pkg/stack"
	"github.com/cloudwebrtc/go-sip-ua/pkg/ua"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/sip/parser"
	"github.com/ghettovoice/gosip/util"
	"github.com/pixelbender/go-sdp/sdp"
)

type CallService struct {
	registry    registry.Registry
	rfc8599     *registry.RFC8599
	callBridges []*CallBridge
	calls       map[*session.Session]*Call
	stack       *stack.SipStack
	ua          *ua.UserAgent
}

func NewCallService(stack *stack.SipStack, ua *ua.UserAgent, registry registry.Registry, rfc8599 *registry.RFC8599) *CallService {
	return &CallService{
		stack:    stack,
		ua:       ua,
		registry: registry,
		rfc8599:  rfc8599,
		calls:    make(map[*session.Session]*Call),
	}
}

func (s *CallService) Init() {
}

func (s *CallService) inviteStateHandler(sess *session.Session, req *sip.Request, resp *sip.Response, state session.Status) {
	logger.Infof("InviteStateHandler: sess %v, state => %v, type => %s", sess.CallID().String(), state, sess.Direction())

	switch state {
	// Handle incoming call.
	case session.InviteReceived:
		offer := &Desc{Type: "offer", SDP: sess.RemoteSdp()}
		sdpSess, _ := offer.Parse()
		transType := ParseTransportType(sdpSess)

		md, err := ParseMediaDescription(sdpSess)
		if err != nil {
			logger.Errorf("ParseTrackInfos error: %v", err)
			return
		}

		src := &Call{sess: sess}
		src.Init(transType, md)
		src.OnOffer(offer)
		s.calls[sess] = src

		if code, err := s.handleIncomingCall(src, req); err != nil {
			logger.Warnf("handleIncomingCall error: %v, code: %s", err, code)
			src.Reject(code, fmt.Sprintf("%v", err))
			s.removeCall(sess)
			return
		}
	// Handle re-INVITE or UPDATE.
	case session.ReInviteReceived:
		logger.Infof("re-INVITE")
		switch sess.Direction() {
		case session.Incoming:
			sess.Accept(200)
		case session.Outgoing:
			//TODO: Need to provide correct answer.
		}

	// Handle 1XX
	case session.EarlyMedia:
		fallthrough
	case session.Provisional:
		call := s.findCall(sess)
		if call != nil {
			//bridge.SetState(EarlyMedia)
			//bridge.src.Provisional((*resp).StatusCode(), (*resp).Reason())
		}
	// Handle 200OK or ACK
	case session.Confirmed:
		//TODO: Add support for forked calls
		call := s.findCall(sess)
		if call != nil && sess.Direction() == session.Outgoing {
			answer := call.sess.RemoteSdp()
			call.OnAnswer(&Desc{Type: "answer", SDP: answer})
			bridge := s.findBridgedCallByCall(call)
			if bridge != nil && bridge.dest.sess == sess && bridge.bType == B2BCall {
				bridge.dest.OnAnswer(&Desc{Type: "answer", SDP: answer})
				bridge.src.Accept(answer)
				BridgeMediaStream(bridge.src.mediaTransport, bridge.dest.mediaTransport)
				bridge.SetState(Confirmed)
			}
		}

	// Handle 4XX+
	case session.Failure:
		fallthrough
	case session.Canceled:
		fallthrough
	case session.Terminated:
		//TODO: Add support for forked calls
		call := s.findCall(sess)
		if call != nil {
			bridge := s.findBridgedCallByCall(call)
			if bridge != nil {
				bridge.Terminate(call)
			}
			s.removeCallBridgeByCall(call)
		}
		s.removeCall(sess)
	}
}

func (s *CallService) handleIncomingCall(src *Call, req *sip.Request) (sip.StatusCode, error) {
	src.Provisional(100, "Trying")

	to, _ := (*req).To()
	from, _ := (*req).From()

	caller := from.Address
	called := to.Address

	displayName := ""
	if from.DisplayName != nil {
		displayName = from.DisplayName.String()
	}

	// Try to find online contact records.
	if contacts, found := s.registry.GetContacts(called); found {
		for _, instance := range *contacts {
			dest, err := s.makeOutgoingCall(caller, displayName, called, instance, src.originalMediaDesc)
			if err != nil {
				logger.Errorf("makeOutgoingCall error: %v", err)
				return 500, err
			}
			s.StoreBridgedCall(src, dest, B2BCall)
			return 0, nil
		}
	}

	if s.rfc8599 != nil {
		// Pushable: try to find pn-params in contact records.
		// Try to push the UA and wait for it to wake up.
		pusher, ok := s.rfc8599.TryPush(called, from)
		if ok {
			instance, err := pusher.WaitContactOnline()
			if err != nil {
				logger.Errorf("Push failed, error: %v", err)
				src.Reject(500, "Push failed")
				return 500, err
			}
			dest, err := s.makeOutgoingCall(caller, displayName, called, instance, src.originalMediaDesc)
			if err != nil {
				logger.Errorf("makeOutgoingCall error: %v", err)
				return 500, err
			}
			s.StoreBridgedCall(src, dest, B2BCall)
			return 0, err
		}
	}

	// try make direct call
	dest, err := s.makeOutgoingCall(caller, displayName, called, nil, src.originalMediaDesc)
	if err != nil {
		logger.Errorf("makeOutgoingCall error: %v", err)
		return 500, err
	}

	s.StoreBridgedCall(src, dest, B2BCall)
	return 0, nil
}

func (s *CallService) StoreBridgedCall(src, dest *Call, bType BridgeType) *CallBridge {
	bridge := &CallBridge{src: src, dest: dest, bType: bType}
	bridge.Init()
	bridge.SetState(Connecting)
	s.callBridges = append(s.callBridges, bridge)
	return bridge
}

func (s *CallService) makeOutgoingCall(caller sip.Uri, displayName string, called sip.Uri, instance *registry.ContactInstance, md *MediaDescription) (*Call, error) {

	profile := account.NewProfile(caller, displayName, nil, 0, s.stack)

	destUri := "sip:" + called.User().String() + "@"

	if instance != nil {
		destUri = destUri + instance.Source + ";transport=" + instance.Transport
	} else {
		destUri = destUri + called.Host() + ";transport=udp"
	}

	recipient, err2 := parser.ParseSipUri(destUri)
	if err2 != nil {
		logger.Error(err2)
	}
	var tpType = TransportTypeStandard

	if instance != nil && instance.SupportIce() {
		tpType = TransportTypeWebRTC
	}

	dest := &Call{}
	dest.Init(tpType, md)
	destOffer, _ := dest.CreateOffer()

	sess, err := s.ua.Invite(profile, called, recipient, &destOffer.SDP)
	if err != nil {
		logger.Errorf("makeOutgoingCall error: %v", err)
		return nil, err
	}
	dest.sess = sess
	s.calls[sess] = dest
	return dest, nil

}

func (s *CallService) findBridgedCallByCall(call *Call) *CallBridge {
	for _, bridge := range s.callBridges {
		if bridge.src == call || bridge.dest == call {
			return bridge
		}
	}
	return nil
}

func (s *CallService) removeCallBridgeByCall(call *Call) {
	for idx, bridge := range s.callBridges {
		if bridge.src == call || bridge.dest == call {
			s.callBridges = append(s.callBridges[:idx], s.callBridges[idx+1:]...)
			return
		}
	}
}

func (s *CallService) findCall(sess *session.Session) *Call {
	if call, found := s.calls[sess]; found {
		return call
	}
	return nil
}

func (s *CallService) removeCall(sess *session.Session) {
	delete(s.calls, sess)
}

func (s *CallService) Shutdown() {
	s.ua.Shutdown()
}

func (s *CallService) Originate(source string, destination string) error {
	logger.Infof("Originate %s => %s", source, destination)

	displayName := "Originate"

	host := b2buaConfig.UaMediaConfig.ExternalRtpAddress

	if host == "" || host == "0.0.0.0" {
		if v, err := util.ResolveSelfIP(); err == nil {
			host = v.String()
		}
	}

	srcUri, err := parser.ParseUri("sip:" + source + "@" + host)
	if err != nil {
		logger.Error(err)
	}

	destUri, err := parser.ParseUri("sip:" + destination + "@" + host)
	if err != nil {
		logger.Error(err)
	}

	var srcCall *Call = nil
	var destCall *Call = nil

	var audioCodecs []*sdp.Format
	var videoCodecs []*sdp.Format

	for _, codec := range defaultAudioCodecs {
		audioCodecs = append(audioCodecs, codec)
	}

	for _, codec := range defaultVideoCodecs {
		videoCodecs = append(videoCodecs, codec)
	}

	originalTrackInfos := map[TrackType]*TrackInfo{
		TrackTypeAudio: {TrackType: TrackTypeAudio, Direction: "sendrecv", Codecs: audioCodecs},
		TrackTypeVideo: {TrackType: TrackTypeVideo, Direction: "sendrecv", Codecs: videoCodecs},
	}

	md := &MediaDescription{
		Tracks: originalTrackInfos,
		Connection: &sdp.Connection{
			Address: host,
		},
	}
	var err2 error = nil
	if contacts, found := s.registry.GetContacts(srcUri); found {
		for _, instance := range *contacts {
			srcCall, err2 = s.makeOutgoingCall(srcUri, displayName, destUri, instance, md)
			if err != nil {
				logger.Errorf("Originate error: %v", err)
				return err2
			}
		}
	}

	if contacts, found := s.registry.GetContacts(destUri); found {
		for _, instance := range *contacts {
			destCall, err2 = s.makeOutgoingCall(destUri, displayName, srcUri, instance, md)
			if err != nil {
				logger.Errorf("Originate error: %v", err)
				return err2
			}
		}
	}

	s.StoreBridgedCall(srcCall, destCall, OriginateCall)
	BridgeMediaStream(srcCall.mediaTransport, destCall.mediaTransport)
	return nil
}
