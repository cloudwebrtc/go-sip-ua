package jitterbuffer

import (
	"github.com/pion/rtp"
)

type JitterBufferType string

const (
	JBOFF         JitterBufferType = "OFF"
	JBUF_FIXED    JitterBufferType = "FIXED"
	JBUF_ADAPTIVE JitterBufferType = "ADAPTIVE"
)

var (
	JBUF_RDIFF_EMA_COEFF = 1024
	JBUF_RDIFF_UP_SPEED  = 512
	JBUF_PUT_TIMEOUT     = 400
)

/** Defines a packet frame */
type packet struct {
	hdr rtp.Header /**< RTP Header                */
	buf []byte     /**< RTP Payload               */
}

type JitterBuffer struct {
	Type JitterBufferType

	min int
	max int

	// Wish size for adaptive mode
	wish int

	payload int

	packets []packet
}

/*
 * @param min    Minimum delay in [frames]
 * @param max    Maximum delay in [packets]
 */
func NewJitterBuffer(jbType JitterBufferType, min, max int) *JitterBuffer {
	return &JitterBuffer{
		Type:    jbType,
		min:     min,
		max:     max,
		wish:    min,
		packets: make([]packet, max),
	}
}
