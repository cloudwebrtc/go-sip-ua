package auth

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ghettovoice/gosip/sip"
)

// currently only Digest and MD5
type Authorization struct {
	realm     string
	qop       string
	nonce     string
	cnonce    string
	opaque    string
	algorithm string
	username  string
	password  string
	uri       string
	response  string
	method    string
	stale     string
	nc        int
	ncHex     string
	domain    string
	other     map[string]string
}

func AuthFromValue(value string) *Authorization {
	auth := &Authorization{
		algorithm: "MD5",
		cnonce:    generateNonce(12),
		opaque:    "",
		stale:     "",
		qop:       "",
		nc:        0,
		ncHex:     "00000000",
		domain:    "",
		other:     make(map[string]string),
	}

	re := regexp.MustCompile(`([\w]+)=("([^"]+)"|([\w]+))`)
	matches := re.FindAllStringSubmatch(value, -1)
	for _, match := range matches {
		value2 := strings.Replace(match[2], "\"", "", -1)
		switch match[1] {
		case "qop":
			auth.qop = value2
		case "realm":
			auth.realm = value2
		case "algorithm":
			auth.algorithm = value2
		case "opaque":
			auth.opaque = value2
		case "nonce":
			auth.nonce = value2
		case "stale":
			auth.stale = value2
		case "domain":
			auth.domain = value2
		default:
			auth.other[match[1]] = value2
		}
	}

	return auth
}

func (auth *Authorization) SetUsername(username string) *Authorization {
	auth.username = username

	return auth
}

func (auth *Authorization) SetUri(uri string) *Authorization {
	auth.uri = uri

	return auth
}

func (auth *Authorization) SetMethod(method string) *Authorization {
	auth.method = method

	return auth
}

func (auth *Authorization) SetPassword(password string) *Authorization {
	auth.password = password

	return auth
}

// calculates Authorization response https://www.ietf.org/rfc/rfc2617.txt
func (auth *Authorization) CalcResponse(request sip.Request) *Authorization {
	auth.nc += 1
	hex := fmt.Sprintf("%x", auth.nc)
	ncHex := "00000000"
	auth.ncHex = ncHex[:len(ncHex)-1-len(hex)] + hex
	// Nc-value = 8LHEX. Max value = 'FFFFFFFF'.
	if auth.nc == 4294967296 {
		auth.nc = 1
		auth.ncHex = "00000001"
	}
	// HA1 = MD5(A1) = MD5(username:realm:password).
	ha1 := md5Hex(auth.username + ":" + auth.realm + ":" + auth.password)
	if auth.qop == "auth" {
		// HA2 = MD5(A2) = MD5(method:digestURI).
		ha2 := md5Hex(auth.method + ":" + auth.uri)
		// Response = MD5(HA1:nonce:nonceCount:credentialsNonce:qop:HA2).
		auth.response = md5Hex(ha1 + ":" + auth.nonce + ":" + auth.ncHex + ":" + auth.cnonce + ":auth:" + ha2)
	} else if auth.qop == "auth-int" {
		// HA2 = MD5(A2) = MD5(method:digestURI:MD5(entityBody)).
		ha2 := md5Hex(auth.method + ":" + auth.uri + ":" + md5Hex(request.Body()))
		// Response = MD5(HA1:nonce:nonceCount:credentialsNonce:qop:HA2).
		auth.response = md5Hex(ha1 + ":" + auth.nonce + ":" + auth.ncHex + ":" + auth.cnonce + ":auth-int:" + ha2)
	} else {
		// HA2 = MD5(A2) = MD5(method:digestURI).
		ha2 := md5Hex(auth.method + ":" + auth.uri)
		// Response = MD5(HA1:nonce:HA2).
		auth.response = md5Hex(ha1 + ":" + auth.nonce + ":" + ha2)
	}
	return auth
}

func (auth *Authorization) String() string {
	digest := fmt.Sprintf(
		`Digest realm="%s",algorithm=%s,nonce="%s",username="%s",uri="%s",response="%s"`,
		auth.realm,
		auth.algorithm,
		auth.nonce,
		auth.username,
		auth.uri,
		auth.response,
	)

	if auth.domain != "" {
		digest += fmt.Sprintf(`domain="%s"`, auth.domain)
	}

	if auth.opaque != "" {
		digest += fmt.Sprintf(`opaque="%s"`, auth.opaque)
	}

	if auth.qop != "" {
		digest += fmt.Sprintf(`qop="%s"`, auth.qop)
		digest += fmt.Sprintf(`cnonce="%s"`, auth.cnonce)
		digest += fmt.Sprintf(`nc="%s"`, auth.ncHex)
	}

	if len(auth.stale) > 0 {
		digest += fmt.Sprintf(`stale=%s`, auth.stale)
	}

	return digest
}

func AuthorizeRequest(request sip.Request, response sip.Response, user, password sip.MaybeString) error {
	if user == nil {
		return fmt.Errorf("authorize request: user is nil")
	}

	var authenticateHeaderName, authorizeHeaderName string
	if response.StatusCode() == 401 {
		// on 401 Unauthorized increase request seq num, add Authorization header and send once again
		authenticateHeaderName = "WWW-Authenticate"
		authorizeHeaderName = "Authorization"
	} else {
		// 407 Proxy authentication
		authenticateHeaderName = "Proxy-Authenticate"
		authorizeHeaderName = "Proxy-Authorization"
	}

	if hdrs := response.GetHeaders(authenticateHeaderName); len(hdrs) > 0 {
		authenticateHeader := hdrs[0].(*sip.GenericHeader)
		auth := AuthFromValue(authenticateHeader.Contents).
			SetMethod(string(request.Method())).
			SetUri(request.Recipient().String()).
			SetUsername(user.String())

		if password != nil {
			auth.SetPassword(password.String())
		}

		auth.CalcResponse(request)

		var authorizationHeader *sip.GenericHeader
		hdrs = request.GetHeaders(authorizeHeaderName)
		if len(hdrs) > 0 {
			authorizationHeader = hdrs[0].(*sip.GenericHeader)
			authorizationHeader.Contents = auth.String()
		} else {
			authorizationHeader = &sip.GenericHeader{
				HeaderName: authorizeHeaderName,
				Contents:   auth.String(),
			}
			request.AppendHeader(authorizationHeader)
		}
	} else {
		return fmt.Errorf("authorize request: header '%s' not found in response", authenticateHeaderName)
	}

	if viaHop, ok := request.ViaHop(); ok {
		viaHop.Params.Add("branch", sip.String{Str: sip.GenerateBranch()})
	}

	if cseq, ok := request.CSeq(); ok {
		cseq.SeqNo++
	}

	return nil
}

type Authorizer interface {
	AuthorizeRequest(request sip.Request, response sip.Response) error
}

type ClientAuthorizer struct {
	user     sip.MaybeString
	password sip.MaybeString
}

func NewClientAuthorizer(u string, p string) *ClientAuthorizer {
	auth := &ClientAuthorizer{
		user:     sip.String{Str: u},
		password: sip.String{Str: p},
	}
	return auth
}

func (auth *ClientAuthorizer) AuthorizeRequest(request sip.Request, response sip.Response) error {
	return AuthorizeRequest(request, response, auth.user, auth.password)
}
