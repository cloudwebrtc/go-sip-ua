# go-sip-ua

SIP UA library for client/b2bua using golang

## Features

- [x] Transports UDP/TCP/TLS/WS/WSS.
- [x] Simple pure Go SIP Client.
- [x] Simple pure Go B2BUA, support RFC8599, Google FCM/Apple PushKit.
- [ ] RTP relay (UDP<-->UDP, WebRTC/ICE<->UDP)
- [ ] WebRTC2SIP Gateway.

## Running the examples

```bash
git clone https://github.com/cloudwebrtc/go-sip-ua
cd go-sip-ua
```

### Client

```bash
# run client
go run examples/client/main.go
```

### B2BUA

B2BUA is a minimal SIP call switch, it registers and calls, and supports UDP/TCP/TLS/WebSockets.

When you need a quick test for TLS/WSS, you can use [mkcert](https://github.com/FiloSottile/mkcert) to create a local self-signed certificate.

```bash
mkdir -p certs
mkcert -key-file certs/key.pem -cert-file certs/cert.pem  localhost 127.0.0.1 ::1 example.com
```

Run the mini b2bua.

```bash
# run b2bua
go run examples/b2bua/main.go -c
```

You can use [dart-sip-ua](https://github.com/flutter-webrtc/dart-sip-ua) or [linphone](https://www.linphone.org/) or [jssip](https://tryit.jssip.net/) to test call or registration, built-in test account 100~400

```
WebSocket: wss://127.0.0.1:5081
SIP URI: 100@127.0.0.1
Authorization User: 100
Password: 100
Display Name: Flutter SIP Client
```

## Dependencies

- [ghettovoice/gosip](https://github.com/ghettovoice/gosip) SIP stack
- [c-bata/go-prompt](https://github.com/c-bata/go-prompt) Console for b2bua
- [pixelbender/go-sdp](https://github.com/pixelbender/go-sdp) SDP
