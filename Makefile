VERSION=$(shell git describe --tags)
GOFLAGS=
GO_LDFLAGS = -ldflags "-s -w"

all: server

clean:
	rm -rf bin

upx:
	upx -9 bin/*

server:
	go build -o bin/simple-b2bua $(GO_LDFLAGS) examples/b2bua/main.go
	go build -o bin/simple-client $(GO_LDFLAGS) examples/client/main.go
	go build -o bin/simple-register $(GO_LDFLAGS) examples/register/main.go

