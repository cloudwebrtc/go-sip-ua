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
	AuthName string
	Realm    string
	Password string
}

// Profile .
type Profile struct {
	User        string
	DisplayName string
	Auth        *AuthInfo
	Expires     uint32
	InstanceID  string
}

//NewProfile .
func NewProfile(
	user string,
	displayName string,
	auth *AuthInfo,
	expires uint32,
) *Profile {
	p := &Profile{
		User:        user,
		DisplayName: displayName,
		Auth:        auth,
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

//RegisterHandler .
type RegisterHandler func(regState RegisterState)
