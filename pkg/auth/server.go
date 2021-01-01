package auth

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/cloudwebrtc/go-sip-ua/pkg/util"
	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
)

var (
	logger log.Logger
)

// AuthSession .
type AuthSession struct {
	nonce   string
	created time.Time
}

type RequestCredentialCallback func(username string) (password string, ha1 string, err error)

// ServerAuthorizer Proxy-Authorization | WWW-Authenticate
type ServerAuthorizer struct {
	// a map[call id]authSession pair
	sessions          map[string]AuthSession
	requestCredential RequestCredentialCallback
	useAuthInt        bool
	realm             string
	log               log.Logger
}

// NewServerAuthorizer .
func NewServerAuthorizer(callback RequestCredentialCallback, realm string, authInt bool, logger log.Logger) *ServerAuthorizer {
	auth := &ServerAuthorizer{
		sessions:          make(map[string]AuthSession),
		requestCredential: callback,
		useAuthInt:        authInt,
		realm:             realm,
	}
	auth.log = logger.WithPrefix("ServerAuthorizer")
	return auth
}

// ServerAuthorizer handles Authenticate requests.
func (auth *ServerAuthorizer) Authenticate(request sip.Request, tx sip.ServerTransaction) (string, bool) {
	logger := auth.log
	logger.Debugf("Request => %s", request.Short())

	from, _ := request.From()

	/*
		TODO: check domain
		to, _ := request.To()
		if to.Address.Host() != from.Address.Host() {
			sendResponse(request, tx, 400, "User in To and From fields do not match.")
			return "", false
		}
	*/

	hdrs := request.GetHeaders("Authorization")
	if len(hdrs) == 0 {
		auth.requestAuthentication(request, tx, from)
		return "", false
	}

	authenticateHeader := hdrs[0].(*sip.GenericHeader)
	authArgs := parseAuthHeader(authenticateHeader.Contents)
	return auth.checkAuthorization(request, tx, authArgs, from)
}

func (auth *ServerAuthorizer) requestAuthentication(request sip.Request, tx sip.ServerTransaction, from *sip.FromHeader) {
	callID, ok := request.CallID()
	if !ok {
		sendResponse(request, tx, 400, "Missing required Call-ID header.")
		return
	}

	response := sip.NewResponseFromRequest(request.MessageID(), request, 401, "Unauthorized", "")
	nonce := generateNonce(8)
	opaque := generateNonce(4)

	digest := sip.NewParams()
	digest.Add("realm", sip.String{Str: "\"" + auth.realm + "\""})
	if auth.useAuthInt {
		digest.Add("qop", sip.String{Str: "\"auth,auth-int\""})
	} else {
		digest.Add("qop", sip.String{Str: "\"auth\""})
	}
	digest.Add("nonce", sip.String{Str: "\"" + nonce + "\""})
	digest.Add("opaque", sip.String{Str: "\"" + opaque + "\""})
	digest.Add("stale", sip.String{Str: "\"false\""})
	digest.Add("algorithm", sip.String{Str: "\"md5\""})

	response.AppendHeader(&sip.GenericHeader{
		HeaderName: "WWW-Authenticate",
		Contents:   "Digest " + digest.ToString(','),
	})

	from.Params.Add("tag", sip.String{Str: generateNonce(8)})
	auth.sessions[callID.String()] = AuthSession{
		nonce:   nonce,
		created: time.Now(),
	}
	response.SetBody("", true)
	util.BuildContactHeader("Contact", request, response, nil)
	tx.Respond(response)
	return
}

func (auth *ServerAuthorizer) checkAuthorization(request sip.Request, tx sip.ServerTransaction,
	authArgs sip.Params, from *sip.FromHeader) (string, bool) {
	callID, ok := request.CallID()
	if !ok {
		sendResponse(request, tx, 400, "Missing required Call-ID header.")
		return "", false
	}

	session, found := auth.sessions[callID.String()]
	if !found {
		auth.requestAuthentication(request, tx, from)
		return "", false
	}

	if username, ok := authArgs.Get("username"); ok && username.String() != from.Address.User().String() {
		auth.requestAuthentication(request, tx, from)
		return "", false
	}

	if nonce, ok := authArgs.Get("nonce"); ok && nonce.String() != session.nonce {
		auth.requestAuthentication(request, tx, from)
		return "", false
	}

	username := from.Address.User().String()
	password, ha1, err := auth.requestCredential(username)
	if err != nil {
		sendResponse(request, tx, 404, "User not found")
		return "", false
	}

	uri, _ := authArgs.Get("uri")
	nc, _ := authArgs.Get("nc")
	cnonce, _ := authArgs.Get("cnonce")
	response, _ := authArgs.Get("response")
	qop, _ := authArgs.Get("qop")
	realm, _ := authArgs.Get("realm")

	result := ""

	// HA1 = MD5(A1) = MD5(username:realm:password).
	if len(ha1) == 0 {
		ha1 = md5Hex(username + ":" + realm.String() + ":" + password)
	}

	if qop != nil && qop.String() == "auth" {
		// HA2 = MD5(A2) = MD5(method:digestURI).
		ha2 := md5Hex(string(request.Method()) + ":" + uri.String())

		// Response = MD5(HA1:nonce:nonceCount:credentialsNonce:qop:HA2).
		result = md5Hex(ha1 + ":" + session.nonce + ":" + nc.String() +
			":" + cnonce.String() + ":auth:" + ha2)
	} else if qop != nil && qop.String() == "auth-int" {
		// HA2 = MD5(A2) = MD5(method:digestURI:MD5(entityBody)).
		ha2 := md5Hex(string(request.Method()) + ":" + uri.String() + ":" + md5Hex(request.Body()))

		// Response = MD5(HA1:nonce:nonceCount:credentialsNonce:qop:HA2).
		result = md5Hex(ha1 + ":" + session.nonce + ":" + nc.String() +
			":" + cnonce.String() + ":auth-int:" + ha2)
	} else {
		// HA2 = MD5(A2) = MD5(method:digestURI).
		ha2 := md5Hex(string(request.Method()) + ":" + uri.String())

		// Response = MD5(HA1:nonce:HA2).
		result = md5Hex(ha1 + ":" + session.nonce + ":" + ha2)
	}

	if result != response.String() {
		sendResponse(request, tx, 403, "Forbidden (Bad auth)")
		return "", false
	}

	return username, true
}

// parseAuthHeader .
func parseAuthHeader(value string) sip.Params {
	authArgs := sip.NewParams()
	re := regexp.MustCompile(`([\w]+)=("([^"]+)"|([\w]+))`)
	matches := re.FindAllStringSubmatch(value, -1)
	for _, match := range matches {
		authArgs.Add(match[1], sip.String{Str: strings.Replace(match[2], "\"", "", -1)})
	}
	return authArgs
}

func generateNonce(size int) string {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func md5Hex(data string) string {
	sum := md5.Sum([]byte(data))
	return hex.EncodeToString(sum[:])
}

// sendResponse .
func sendResponse(request sip.Request, tx sip.ServerTransaction, statusCode sip.StatusCode, reason string) {
	response := sip.NewResponseFromRequest(request.MessageID(), request, statusCode, reason, "")
	tx.Respond(response)
}
