package b2bua

import (
	"context"
	"fmt"
	"math/rand"
	"net"

	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v3"
)

var (
	webrtcSettings webrtc.SettingEngine
)

const (
	mimeTypeH264 = "video/h264"
	mimeTypeOpus = "audio/opus"
	mimeTypeVP8  = "video/vp8"
	mimeTypeVP9  = "video/vp9"
	mineTypePCMA = "audio/PCMA"
)

func init() {
	webrtcSettings = webrtc.SettingEngine{}
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IP{0, 0, 0, 0},
		Port: 50160,
	})
	if err != nil {
		panic(err)
	}
	webrtcSettings.SetICEUDPMux(webrtc.NewICEUDPMux(nil, udpListener))
}

const DefaultPayloadTypeOpus = 111

var (
	setting webrtc.SettingEngine
	cfg     = webrtc.Configuration{
		SDPSemantics: webrtc.SDPSemanticsUnifiedPlanWithFallback,
	}
)

type WebRTCTransport struct {
	pc          *webrtc.PeerConnection
	mediaEngine webrtc.MediaEngine
	api         *webrtc.API
	answer      webrtc.SessionDescription
	offer       webrtc.SessionDescription
	track       *webrtc.TrackLocalStaticRTP

	closed utils.AtomicBool
	ctx    context.Context
	cancel context.CancelFunc

	trackInfos []*TrackInfo
}

func NewWebRTCTransport(trackInfos []*TrackInfo) *WebRTCTransport {
	c := &WebRTCTransport{
		trackInfos: trackInfos,
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.closed.Set(false)
	return c
}

func (c *WebRTCTransport) Type() TransportType {
	return TransportTypeRTC
}

func (c *WebRTCTransport) Init(callConfig CallConfig) error {
	// Create a MediaEngine object to configure the supported codec
	m := &webrtc.MediaEngine{}

	for _, codec := range []webrtc.RTPCodecParameters{
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMU, ClockRate: 8000, Channels: 1, SDPFmtpLine: "", RTCPFeedback: nil},
			PayloadType:        0,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMA, ClockRate: 8000, Channels: 1, SDPFmtpLine: "", RTCPFeedback: nil},
			PayloadType:        8,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: mimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1", RTCPFeedback: nil},
			PayloadType:        111,
		},
	} {
		if err := m.RegisterCodec(codec, webrtc.RTPCodecTypeAudio); err != nil {
			return err
		}
	}

	videoRTCPFeedback := []webrtc.RTCPFeedback{{"goog-remb", ""}, {"ccm", "fir"}, {"nack", ""}, {"nack", "pli"}}

	for _, codec := range []webrtc.RTPCodecParameters{
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: mimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f", RTCPFeedback: videoRTCPFeedback},
			PayloadType:        125,
		},
	} {
		if err := m.RegisterCodec(codec, webrtc.RTPCodecTypeVideo); err != nil {
			return err
		}
	}

	// Create a InterceptorRegistry. This is the user configurable RTP/RTCP Pipeline.
	// This provides NACKs, RTCP Reports and other features. If you use `webrtc.NewPeerConnection`
	// this is enabled by default. If you are manually managing You MUST create a InterceptorRegistry
	// for each PeerConnection.
	i := &interceptor.Registry{}

	// Use the default set of Interceptors
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		panic(err)
	}

	// Create the API object with the MediaEngine
	api := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(i))

	// Prepare the configuration
	config := webrtc.Configuration{
		ICEServers:   []webrtc.ICEServer{},
		SDPSemantics: webrtc.SDPSemanticsUnifiedPlanWithFallback,
		//RTCPMuxPolicy: webrtc.RTCPMuxPolicyRequire,
		BundlePolicy: webrtc.BundlePolicyBalanced,
	}

	// Create a new RTCPeerConnection
	pc, err := api.NewPeerConnection(config)
	if err != nil {
		panic(err)
	}

	c.pc = pc

	c.pc.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState) {
		logger.Infof("ICE Connection State has changed: %s\n", connectionState.String())
	})
	c.pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logger.Infof("PeerConnection State has changed: %s\n", state.String())
	})
	return nil
}

func (c *WebRTCTransport) Close() error {
	if c.closed.Get() {
		return nil
	}
	c.closed.Set(true)
	c.cancel()
	return c.pc.Close()
}

func (c *WebRTCTransport) CreateOffer() (*Desc, error) {
	var err error = nil

	c.track, err = webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMU},
		fmt.Sprintf("audio-%d", rand.Uint32()),
		fmt.Sprintf("rtc-%d", rand.Uint32()),
	)

	if err != nil {
		logger.Errorf("NewTrack: panic => %v", err)
		return nil, err
	}

	if _, err = c.pc.AddTrack(c.track); err != nil {
		logger.Errorf("AddTrack: panic => %v", err)
		return nil, err
	}

	c.offer, err = c.pc.CreateOffer(nil)
	if err != nil {
		logger.Errorf("CreateOffer: panic => %v", err)
		return nil, err
	}
	gatherComplete := webrtc.GatheringCompletePromise(c.pc)
	if err = c.pc.SetLocalDescription(c.offer); err != nil {
		logger.Errorf("SetLocalDescription: panic => %v", err)
		return nil, err
	}
	<-gatherComplete
	c.offer = *c.pc.LocalDescription()
	return &Desc{SDP: c.offer.SDP, Type: "offer"}, nil
}

func (c *WebRTCTransport) OnAnswer(answer *Desc) error {
	c.answer = webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answer.SDP,
	}
	if err := c.pc.SetRemoteDescription(c.answer); err != nil {
		logger.Errorf("SetRemoteDescription: panic => %v", err)
		return err
	}
	return nil
}

func (c *WebRTCTransport) OnOffer(offer *Desc) error {

	c.pc.OnTrack(func(track *webrtc.TrackRemote, recevier *webrtc.RTPReceiver) {
		buf := make([]byte, 1500)
		for {
			if c.closed.Get() {
				logger.Infof("OnTrack: stop now!")
				break
			}
			// Read
			n, _, readErr := track.Read(buf)
			if readErr != nil {
				logger.Errorf("track.Read: readErr => %v", readErr)
				break
			}
			logger.Infof("OnTrack: read %d bytes", n)
			///TODO: c.stream.OnReadPacket(buf[:n], false)
		}

	})

	var err error = nil
	c.track, err = webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMU},
		fmt.Sprintf("audio-%d", rand.Uint32()),
		fmt.Sprintf("audio-%d", rand.Uint32()),
	)

	if err != nil {
		logger.Errorf("NewTrack: panic => %v", err)
		return err
	}

	if _, err = c.pc.AddTrack(c.track); err != nil {
		logger.Errorf("AddTrack: panic => %v", err)
		return err
	}

	desc := webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offer.SDP,
	}

	if err := c.pc.SetRemoteDescription(desc); err != nil {
		logger.Errorf("SetRemoteDescription: panic => %v", err)
		return err
	}
	return nil
}

func (c *WebRTCTransport) CreateAnswer() (*Desc, error) {
	var err error = nil
	c.answer, err = c.pc.CreateAnswer(nil)
	if err != nil {
		logger.Errorf("CreateAnswer: panic => %v", err)
		return nil, err
	}

	gatherComplete := webrtc.GatheringCompletePromise(c.pc)
	if err = c.pc.SetLocalDescription(c.answer); err != nil {
		logger.Errorf("SetLocalDescription: panic => %v", err)
		return nil, err
	}
	<-gatherComplete
	c.answer = *c.pc.LocalDescription()

	return &Desc{SDP: c.answer.SDP, Type: "answer"}, nil
}

func (c *WebRTCTransport) HandleRtcpFb(rtpSender *webrtc.RTPSender) {
	// Read incoming RTCP packets
	// Before these packets are returned they are processed by interceptors. For things
	// like NACK this needs to be called.
	go func() {
		rtcpBuf := make([]byte, 1500)
		for {
			n, _, rtcpErr := rtpSender.Read(rtcpBuf)
			if rtcpErr != nil {
				return
			}
			bytes := rtcpBuf[:n]
			pkts, err := rtcp.Unmarshal(bytes)
			if err != nil {
				logger.Errorf("Unmarshal rtcp receiver packets err %v", err)
			}
			var fwdPkts []rtcp.Packet
			pliOnce := true
			firOnce := true
			var (
				maxRatePacketLoss  uint8
				expectedMinBitrate uint64
			)
			for _, pkt := range pkts {
				switch p := pkt.(type) {
				case *rtcp.PictureLossIndication:
					if pliOnce {
						fwdPkts = append(fwdPkts, p)
						logger.Infof("PictureLossIndication")
						//hi.CameraSendKeyFrame()
						pliOnce = false
					}
				case *rtcp.FullIntraRequest:
					if firOnce {
						fwdPkts = append(fwdPkts, p)
						//logger.Infof("FullIntraRequest")
						firOnce = false
					}
				case *rtcp.ReceiverEstimatedMaximumBitrate:
					if expectedMinBitrate == 0 || expectedMinBitrate > uint64(p.Bitrate) {
						expectedMinBitrate = uint64(p.Bitrate)
						//hi.CameraUpdateBitrate(uint32(expectedMinBitrate / 1024))
						logger.Infof("ReceiverEstimatedMaximumBitrate %d", expectedMinBitrate/1024)
					}
				case *rtcp.ReceiverReport:
					for _, r := range p.Reports {
						if maxRatePacketLoss == 0 || maxRatePacketLoss < r.FractionLost {
							maxRatePacketLoss = r.FractionLost
							logger.Infof("maxRatePacketLoss %d", maxRatePacketLoss)
						}
					}
				case *rtcp.TransportLayerNack:
				}
			}
		}
	}()

}

// InitWebRTC init WebRTCTransport setting
func InitWebRTC(nat1to1 []string, icelite bool, iceServers []webrtc.ICEServer, icePortStart, icePortEnd uint16, iceSinglePort int) error {
	var err error
	if icePortStart != 0 || icePortEnd != 0 {
		err = setting.SetEphemeralUDPPortRange(icePortStart, icePortEnd)
		if err != nil {
			logger.Errorf("SetEphemeralUDPPortRange: err => %v", err)
			return err
		}
	}

	if len(nat1to1) > 0 {
		setting.SetNAT1To1IPs(nat1to1, webrtc.ICECandidateTypeHost)
	}
	if icelite {
		setting.SetLite(icelite)
		cfg.ICEServers = []webrtc.ICEServer{}
	} else {
		cfg.ICEServers = iceServers
	}

	setting.DisableMediaEngineCopy(true)

	if iceSinglePort != 0 {
		logger.Info("Listen on ", "single-port")
		udpListener, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IP{0, 0, 0, 0},
			Port: iceSinglePort,
		})
		if err != nil {
			panic(err)
		}
		setting.SetICEUDPMux(webrtc.NewICEUDPMux(nil, udpListener))
	}

	return err
}
