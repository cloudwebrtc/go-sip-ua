module github.com/cloudwebrtc/go-sip-ua

go 1.13

replace github.com/ghettovoice/gosip v0.0.0-20200807105127-dadd6a686e38 => ../gosip

require (
	github.com/c-bata/go-prompt v0.2.3
	github.com/ghettovoice/gosip v0.0.0-20201214141153-0aff90dbe5be
	github.com/google/uuid v1.1.1
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mattn/go-tty v0.0.3 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/pixelbender/go-sdp v1.1.0
	github.com/pkg/term v0.0.0-20200520122047-c3ffed290a03 // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
)
