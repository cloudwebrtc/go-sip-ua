module github.com/cloudwebrtc/go-sip-ua

go 1.13

replace github.com/ghettovoice/gosip v0.0.0-20200807105127-dadd6a686e38 => ../gosip

require (
	github.com/c-bata/go-prompt v0.2.5
	github.com/ghettovoice/gosip v0.0.0-20200807105127-dadd6a686e38
	github.com/google/uuid v1.1.3
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/pixelbender/go-sdp v1.1.0
	github.com/sirupsen/logrus v1.7.0
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
)
