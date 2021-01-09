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
	URI         sip.Uri
	DisplayName string

	AuthInfo   *AuthInfo
	Expires    uint32
	InstanceID string

	Server string

	ContactParams map[string]string
}

func (p *Profile) Contact() *sip.Address {
	contact := &sip.Address{
		Uri:    p.URI.Clone(),
		Params: sip.NewParams(),
	}
	if p.InstanceID != "nil" {
		contact.Params.Add("+sip.instance", sip.String{Str: p.InstanceID})
	}

	for key, value := range p.ContactParams {
		contact.Params.Add(key, sip.String{Str: value})
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
		URI:         uri,
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
