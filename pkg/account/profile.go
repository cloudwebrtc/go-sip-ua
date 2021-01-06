package account

import (
	"fmt"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
	"github.com/google/uuid"
)

var (
	logger log.Logger
)

func init() {
	logger = log.NewDefaultLogrusLogger().WithPrefix("UserAgent")
}

//AuthInfo .
type AuthInfo struct {
	AuthUser string
	Realm    string
	Password string
	Ha1      string
}

// Profile .
type Profile struct {
	Uri         sip.Uri
	DisplayName string

	AuthInfo   *AuthInfo
	Expires    uint32
	InstanceID string

	Server string
}

func (p *Profile) Contact() *sip.Address {
	contact := &sip.Address{
		Uri:    p.Uri.Clone(),
		Params: sip.NewParams(),
	}
	if p.InstanceID != "nil" {
		contact.Params.Add("+sip.instance", sip.String{Str: p.InstanceID})
	}

	//TODO: Add more necessary parameters.
	//etc: ip:port, transport=udp|tcp, +sip.ice, +sip.instance, +sip.pnsreg,

	return contact
}

//NewProfile .
func NewProfile(
	uri sip.Uri,
	displayName string,
	authInfo *AuthInfo,
	expires uint32,
) *Profile {
	p := &Profile{
		Uri:         uri,
		DisplayName: displayName,
		AuthInfo:    authInfo,
		Expires:     expires,
	}
	uid, err := uuid.NewUUID()
	if err != nil {
		logger.Errorf("could not create UUID: %v", err)
	}
	p.InstanceID = fmt.Sprintf(`"<%s>"`, uid.URN())
	return p
}

//RegisterState .
type RegisterState struct {
	Account    Profile
	StatusCode sip.StatusCode
	Reason     string
	Expiration uint32
	Response   sip.Response
}
