package webrtc

type TrackImpl struct {
	name string
}

func (t *TrackImpl) Name() string {
	return t.name
}

func (t *TrackImpl) WriteRTP(buf []byte) {

}

func (t *TrackImpl) WriteRTCP(buf []byte) {

}

func (t *TrackImpl) ReadRTP() <-chan []byte {
	return nil
}

func (t *TrackImpl) ReadRTCP() <-chan []byte {
	return nil
}
