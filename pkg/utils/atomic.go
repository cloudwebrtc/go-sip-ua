package utils

import "sync/atomic"

type AtomicBool int32

func (a *AtomicBool) Set(value bool) (swapped bool) {
	if value {
		return atomic.SwapInt32((*int32)(a), 1) == 0
	}
	return atomic.SwapInt32((*int32)(a), 0) == 1
}

func (a *AtomicBool) Get() bool {
	return atomic.LoadInt32((*int32)(a)) != 0
}

type AtomicUInt32 uint32

func (ai *AtomicUInt32) Set(value uint32) (result uint32) {
	return atomic.SwapUint32((*uint32)(ai), value)
}

func (ai *AtomicUInt32) Get() uint32 {
	return atomic.LoadUint32((*uint32)(ai))
}

func (ai *AtomicUInt32) Incr() {
	ai.Set(ai.Get() + 1)
}

func (ai *AtomicUInt32) Decr() {
	ai.Set(ai.Get() - 1)
}
