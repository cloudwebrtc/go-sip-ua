package ua

import (
	"context"
	"strconv"
	"time"

	"github.com/cloudwebrtc/go-sip-ua/pkg/account"
	"github.com/cloudwebrtc/go-sip-ua/pkg/auth"
	"github.com/ghettovoice/gosip/sip"
	"github.com/ghettovoice/gosip/util"
)

type Register struct {
	ua         *UserAgent
	timer      *time.Timer
	profile    *account.Profile
	authorizer *auth.ClientAuthorizer
	recipient  sip.SipUri
	request    *sip.Request
	ctx        context.Context
	cancel     context.CancelFunc
	data       interface{}
}

func NewRegister(ua *UserAgent, profile *account.Profile, recipient sip.SipUri, data interface{}) *Register {
	r := &Register{
		ua:        ua,
		profile:   profile,
		recipient: recipient,
		request:   nil,
		data:      data,
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	return r
}

func (r *Register) SendRegister(expires uint32) error {

	ua := r.ua
	profile := r.profile
	recipient := r.recipient

	from := &sip.Address{
		Uri:    profile.URI,
		Params: sip.NewParams().Add("tag", sip.String{Str: util.RandString(8)}),
	}

	to := &sip.Address{
		Uri: profile.URI,
	}

	contact := profile.Contact()

	if r.request == nil || expires == 0 {
		request, err := ua.buildRequest(sip.REGISTER, from, to, contact, recipient, nil)
		if err != nil {
			ua.Log().Errorf("Register: err = %v", err)
			return err
		}
		expiresHeader := sip.Expires(expires)
		(*request).AppendHeader(&expiresHeader)
		r.request = request
	} else {
		cseq, _ := (*r.request).CSeq()
		cseq.SeqNo++
		cseq.MethodName = sip.REGISTER

		(*r.request).RemoveHeader("Expires")
		// replace Expires header.
		expiresHeader := sip.Expires(expires)
		(*r.request).AppendHeader(&expiresHeader)
	}

	if profile.AuthInfo != nil && r.authorizer == nil {
		r.authorizer = auth.NewClientAuthorizer(profile.AuthInfo.AuthUser, profile.AuthInfo.Password)
	}

	resp, err := ua.RequestWithContext(r.ctx, *r.request, r.authorizer, true)

	if err != nil {
		ua.Log().Errorf("Request [%s] failed, err => %v", sip.REGISTER, err)
		if ua.RegisterStateHandler != nil {
			var code sip.StatusCode
			var reason string
			if _, ok := err.(*sip.RequestError); ok {
				reqErr := err.(*sip.RequestError)
				code = sip.StatusCode(reqErr.Code)
				reason = reqErr.Reason
			} else {
				code = 500
				reason = err.Error()
			}

			state := account.RegisterState{
				Account:    profile,
				Response:   nil,
				StatusCode: sip.StatusCode(code),
				Reason:     reason,
				Expiration: 0,
				UserData:   r.data,
			}
			ua.RegisterStateHandler(state)
		}
	}
	if resp != nil {
		stateCode := resp.StatusCode()
		ua.Log().Debugf("%s resp %d => %s", sip.REGISTER, stateCode, resp.String())
		if ua.RegisterStateHandler != nil {
			var expires uint32 = 0
			hdrs := resp.GetHeaders("Expires")
			if len(hdrs) > 0 {
				expires = uint32(*(hdrs[0]).(*sip.Expires))
			} else {
				hdrs = resp.GetHeaders("Contact")
				if len(hdrs) > 0 {
					if cexpires, cexpirescok := (hdrs[0].(*sip.ContactHeader)).Params.Get("expires"); cexpirescok {
						cexpiresint, _ := strconv.Atoi(cexpires.String())
						expires = uint32(cexpiresint)
					}
				}
			}
			state := account.RegisterState{
				Account:    profile,
				Response:   resp,
				StatusCode: resp.StatusCode(),
				Reason:     resp.Reason(),
				Expiration: expires,
				UserData:   r.data,
			}
			if expires > 0 {
				go func() {
					if r.timer == nil {
						r.timer = time.NewTimer(time.Second * time.Duration(expires-10))
					} else {
						r.timer.Reset(time.Second * time.Duration(expires-10))
					}
					select {
					case <-r.timer.C:
						r.SendRegister(expires)
					case <-r.ctx.Done():
						return
					}
				}()
			} else if expires == 0 {
				if r.timer != nil {
					r.timer.Stop()
					r.timer = nil
				}
				r.request = nil
			}
			ua.RegisterStateHandler(state)
		}
	}

	return nil
}

func (r *Register) Stop() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.cancel()
}
