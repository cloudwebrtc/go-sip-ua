module github.com/cloudwebrtc/go-sip-ua

go 1.13

replace github.com/ghettovoice/gosip v0.0.0-20200807105127-dadd6a686e38 => ../gosip

require (
	cloud.google.com/go/firestore v1.4.0 // indirect
	firebase.google.com/go v3.13.0+incompatible
	github.com/c-bata/go-prompt v0.2.5
	github.com/ghettovoice/gosip v0.0.0-20210125110624-911985a2da41
	github.com/google/uuid v1.2.0
	github.com/kr/pretty v0.2.0 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/pixelbender/go-sdp v1.1.0
	github.com/sirupsen/logrus v1.7.0
	github.com/x-cray/logrus-prefixed-formatter v0.5.2
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	google.golang.org/api v0.36.0
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)
