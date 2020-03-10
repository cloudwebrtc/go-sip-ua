# go-sip-ua

SIP UA library for client/b2bua using golang

## Running the examples

```bash
git clone https://github.com/cloudwebrtc/go-sip-ua
cd go-sip-ua
# run b2bua
go run examples/b2bua/main.go -c
# run client
go run examples/client/main.go
```

## Dependencies

- [ghettovoice/gosip](https://github.com/ghettovoice/gosip) SIP stack
- [c-bata/go-prompt](https://github.com/c-bata/go-prompt) Console for b2bua
- [pixelbender/go-sdp](github.com/pixelbender/go-sdp) SDP
