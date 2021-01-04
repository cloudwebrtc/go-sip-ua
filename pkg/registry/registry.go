package registry

import "github.com/ghettovoice/gosip/sip"

type ContactInstance struct {
	Contact     *sip.ContactHeader
	RegExpires  uint32
	LastUpdated uint32
	Source      string
	UserAgent   string
	Transport   string
}

func (c *ContactInstance) GetPNParams() *PNParams {
	params := c.Contact.Address.UriParams()
	if provider, ok := params.Get("pn-provider"); ok {
		param, _ := params.Get("pn-param")
		prid, found := params.Get("pn-prid")
		if !found || prid == nil {
			prid = sip.String{Str: ""}
		}
		pn := &PNParams{
			Provider: provider.String(),
			Param:    param.String(),
			PRID:     prid.String(),
		}
		return pn
	}
	return nil
}

func NewContactInstanceForRequest(request sip.Request) *ContactInstance {
	headers := request.GetHeaders("Expires")
	var expires sip.Expires = 0
	if len(headers) > 0 {
		expires = *headers[0].(*sip.Expires)
	}
	contacts, _ := request.Contact()
	userAgent := request.GetHeaders("User-Agent")[0].(*sip.UserAgentHeader)
	instance := &ContactInstance{
		Source:     request.Source(),
		RegExpires: uint32(expires),
		Contact:    contacts.Clone().(*sip.ContactHeader),
		UserAgent:  userAgent.String(),
		Transport:  request.Transport(),
	}
	return instance
}

// Registry Address-of-Record registry
type Registry interface {
	AddAor(aor sip.Uri, instance *ContactInstance) error
	RemoveAor(aor sip.Uri) error
	AorIsRegistered(aor sip.Uri) bool
	UpdateContact(aor sip.Uri, instance *ContactInstance) error
	RemoveContact(aor sip.Uri, instance *ContactInstance) error
	GetContacts(aor sip.Uri) (*map[string]*ContactInstance, bool)
	GetAllContacts() map[sip.Uri]map[string]*ContactInstance
}
