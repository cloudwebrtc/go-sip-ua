package rtp

type RTP interface {
	WriteRTP(buf []byte)
	WriteRTCP(buf []byte)
	ReadRTP() <-chan []byte
	ReadRTCP() <-chan []byte
}
