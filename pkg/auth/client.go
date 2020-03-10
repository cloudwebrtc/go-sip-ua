package auth

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/ghettovoice/gosip/sip"
)

// currently only Digest and MD5
type Authorization struct {
	realm     string
	nonce     string
	algorithm string
	username  string
	password  string
	uri       string
	response  string
	method    string
	other     map[string]string
}

func AuthFromValue(value string) *Authorization {
	auth := &Authorization{
		algorithm: "MD5",
		other:     make(map[string]string),
	}

	re := regexp.MustCompile(`([\w]+)=("([^"]+)"|([\w]+))`)
	matches := re.FindAllStringSubmatch(value, -1)
	for _, match := range matches {
		value2 := strings.Replace(match[2], "\"", "", -1)
		switch match[1] {
		case "realm":
			auth.realm = value2
		case "algorithm":
			auth.algorithm = value2
		case "nonce":
			auth.nonce = value2
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

func (auth *Authorization) CalcResponse() *Authorization {
	auth.response = calcResponse(
		auth.username,
		auth.realm,
		auth.password,
		auth.method,
		auth.uri,
		auth.nonce,
	)

	return auth
}

func (auth *Authorization) String() string {
	return fmt.Sprintf(
		`Digest realm="%s",algorithm=%s,nonce="%s",username="%s",uri="%s",response="%s"`,
		auth.realm,
		auth.algorithm,
		auth.nonce,
		auth.username,
		auth.uri,
		auth.response,
	)
}

// calculates Authorization response https://www.ietf.org/rfc/rfc2617.txt
func calcResponse(username string, realm string, password string, method string, uri string, nonce string) string {
	calcA1 := func() string {
		encoder := md5.New()
		encoder.Write([]byte(username + ":" + realm + ":" + password))

		return hex.EncodeToString(encoder.Sum(nil))
	}
	calcA2 := func() string {
		encoder := md5.New()
		encoder.Write([]byte(method + ":" + uri))

		return hex.EncodeToString(encoder.Sum(nil))
	}

	encoder := md5.New()
	encoder.Write([]byte(calcA1() + ":" + nonce + ":" + calcA2()))

	return hex.EncodeToString(encoder.Sum(nil))
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

		auth.CalcResponse()

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
