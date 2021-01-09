package registry

import (
	"fmt"
	"log"
	"time"

	"github.com/ghettovoice/gosip/sip"
)

const (
	DefaultPNTimeout = 30 // s
)

type PNParams struct {
	Provider string // PNS Provider (apns|fcm|other)
	Param    string
	PRID     string
	PURR     string
	Expires  uint32 //TODO:
}

func (p *PNParams) String() string {
	return "pn-provider: " + p.Provider + ", pn-param: " + p.Param + ", pn-prid: " + p.PRID
}

func (p *PNParams) Equals(other *PNParams) bool {
	return p.Provider == other.Provider && p.Param == other.Param && p.PRID == other.PRID
}

//Disabled https://tools.ietf.org/html/rfc8599#section-4.1.2
func (p *PNParams) Disabled() bool {
	return len(p.PRID) == 0
}

type PushCallback func(pn *PNParams, payload map[string]string) error

type RFC8599 struct {
	PushCallback PushCallback
	records      map[PNParams]sip.Uri
	pushers      map[PNParams]*Pusher
}

func NewRFC8599(callback PushCallback) *RFC8599 {
	rfc := &RFC8599{
		PushCallback: callback,
		records:      make(map[PNParams]sip.Uri),
		pushers:      make(map[PNParams]*Pusher),
	}
	return rfc
}

func (r *RFC8599) PNRecords() map[PNParams]sip.Uri {
	return r.records
}

func (r *RFC8599) HandleContactInstance(aor sip.Uri, instance *ContactInstance) {
	pn := instance.GetPNParams()
	if pn != nil {
		disable := pn.Disabled()
		if disable {
			//Remove pn record.
			for params, uri := range r.records {
				if uri.User() == aor.User() {
					delete(r.records, params)
				}
			}

			return
		}

		// Add pn record.
		if _, ok := r.records[*pn]; !ok {
			r.records[*pn] = aor
		}

		//for params, aor := range r.records {
		//	fmt.Printf("\n\n\naor %v => params %v\n\n\n", aor, params.String())
		//}

		for params, pusher := range r.pushers {
			if params.Equals(pn) {
				pusher.CH <- instance
				delete(r.pushers, params)
				break
			}
		}
	}
}

func (r *RFC8599) TryPush(aor sip.Uri, from *sip.FromHeader) (*Pusher, bool) {
	for params, uri := range r.records {

		if uri.User() == aor.User() {
			displayName := ""
			if from.DisplayName != nil {
				displayName = from.DisplayName.String()
			}
			payload := map[string]string{
				"caller_id":      from.Address.User().String(),
				"caller_name":    displayName,
				"caller_id_type": "number",
				"has_video":      "false",
			}

			if err := r.PushCallback(&params, payload); err != nil {
				//push failed,.
				log.Printf("Push failed: %v", err)
				return nil, false
			}
			pusher := NewPusher()
			r.pushers[params] = pusher
			return pusher, true
		}
	}
	return nil, false
}

type Pusher struct {
	CH    chan *ContactInstance
	abort chan int
}

func NewPusher() *Pusher {
	pn := &Pusher{
		CH:    make(chan *ContactInstance, 1),
		abort: make(chan int, 1),
	}
	return pn
}

func (pn *Pusher) WaitContactOnline() (*ContactInstance, error) {
	t := time.NewTicker(time.Second * time.Duration(DefaultPNTimeout))
	for {
		select {
		case <-pn.abort:
			return nil, fmt.Errorf("Abort")
		case <-t.C:
			return nil, fmt.Errorf("Timeout")
		case instance := <-pn.CH:
			return instance, nil
		}
	}
}

//Abort caller cancelled the call
func (pn *Pusher) Abort() {
	pn.abort <- 1
}
