package media

type Track interface {
	Name() string
	WriteRTP(buf []byte)
	WriteRTCP(buf []byte)
	ReadRTP() <-chan []byte
	ReadRTCP() <-chan []byte
}
