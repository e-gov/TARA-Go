/*
Package tara provides a client for authenticating with the TARA authentication
service provided by the Information System Authority of the Republic of
Estonia.

This simply wraps an OpenID Connect client with some specific choices and
adjustments made by TARA.
*/
package tara

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"internal/session"
)

const (
	// DefaultHTTPTimeout is the default roundtrip timeout for requests
	// sent to the OpenID Connect Provider.
	DefaultHTTPTimeout = 15 * time.Second

	// DefaultStateCookie is the default name of the state cookie.
	DefaultStateCookie = "tara-state"

	// DefaultNonceCookie is the default name of the nonce cookie.
	DefaultNonceCookie = "tara-nonce"
)

// Client is a TARA client.
type Client interface {
	// AuthenticationRequest redirects the user-agent to send an
	// authentication request to the authorization endpoint.
	//
	// If the returned error is non-nil, then Client has not written
	// anything to w yet: the caller must report (and log) the error.
	AuthenticationRequest(http.ResponseWriter) error

	// AuthenticationResponse handles a response from the authorization
	// endpoint (via user-agent redirect). If successful, it contacts the
	// token endpoint to obtain claims about the authenticated end-user.
	//
	// A returned BadRequestError indicates that r was invalid in some way.
	// Otherwise it was an internal server or TARA error.
	AuthenticationResponse(*http.Request) (session.UserData, error)

	// ClearCookies tells the user-agent to drop all cookies set by Client.
	ClearCookies(http.ResponseWriter)
}

// BadRequestError is returned from AuthenticationResponse if the request sent
// to the redirect URI was invalid.
type BadRequestError struct {
	Err error
}

// Cause returns the underlying error.
func (b BadRequestError) Cause() error { return b.Err }

// Error formats the BadRequestError as a string.
func (b BadRequestError) Error() string { return "bad request: " + b.Err.Error() }

// Conf contains the configuration values for the TARA authentication client.
type Conf struct {
	// Issuer is OpenID Connect Provider's Issuer Identifier.
	Issuer string

	// AuthorizationEndpoint, TokenEndpoint, and JWKSURI specify
	// configuration information for the OpenID Connect Provider.
	//
	// If none of these values are specified, then OpenID Connect Discovery
	// is attempted with the Issuer Identifier to obtain the configuration.
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string

	RedirectionURI   string // Redirection URI of the Relying Party.
	ClientIdentifier string // Client Identifier of the Relying Party.
	ClientSecret     string // Client Secret of the Relying Party.

	// Scope specifies additional scope values of the authorization
	// request. For TARA, this enumerates the allowed authentication
	// methods. Only "idcard", "mid", and "smartid" values are allowed.
	Scope []string

	// HTTPTimeout specifies the roundtrip timeout used for HTTP requests
	// sent to the OpenID Connect Provider. If zero, then
	// DefaultHTTPTimeout is used instead.
	HTTPTimeout time.Duration

	// StateCookie is the name of the state cookie set by this package. If
	// not specified, then DefaultStateCookie is used.
	StateCookie string

	// NonceCookie is the name of the nonce cookie set by this package. If
	// not specified, then DefaultNonceCookie is used.
	NonceCookie string

	// RequestLogger is an optional logger for client and TARA request
	// information. If nil, then not logged.
	RequestLogger *log.Logger

	// SecurityLogger is an optional separate logger for security events.
	// If nil, then RequestLogger is used. If RequestLogger is also nil,
	// then not logged.
	SecurityLogger *log.Logger
}

func (c Conf) shouldDiscover() bool {
	return c.AuthorizationEndpoint == "" &&
		c.TokenEndpoint == "" &&
		c.JWKSURI == ""
}

func (c Conf) httpTimeout() time.Duration {
	if c.HTTPTimeout != 0 {
		return c.HTTPTimeout
	}
	return DefaultHTTPTimeout
}

func (c Conf) stateCookie() string {
	if c.StateCookie != "" {
		return c.StateCookie
	}
	return DefaultStateCookie
}

func (c Conf) nonceCookie() string {
	if c.NonceCookie != "" {
		return c.NonceCookie
	}
	return DefaultNonceCookie
}

type client struct {
	conf       Conf
	cookiePath string
	amr        map[string]struct{} // Set of allowed authentication methods.
	verifier   *oidc.IDTokenVerifier
	oauth      oauth2.Config
	http       *http.Client // HTTP client used for all external requests.
}

// NewClient creates a new TARA client from the provided configuration.
func NewClient(conf Conf) (Client, error) {
	if conf.Issuer == "" {
		return nil, errors.New("missing mandatory Issuer")
	}
	if conf.RedirectionURI == "" {
		return nil, errors.New("missing mandatory Redirection URI")
	}
	redirectURL, err := url.Parse(conf.RedirectionURI)
	if err != nil {
		return nil, errors.Wrap(err, "parse Redirection URI")
	}
	c := &client{
		conf:       conf,
		cookiePath: redirectURL.EscapedPath(),
		amr:        make(map[string]struct{}),
		oauth: oauth2.Config{
			ClientID:     conf.ClientIdentifier,
			ClientSecret: conf.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  conf.AuthorizationEndpoint,
				TokenURL: conf.TokenEndpoint,
			},
			RedirectURL: conf.RedirectionURI,
			Scopes:      []string{oidc.ScopeOpenID},
		},
		http: &http.Client{Timeout: conf.httpTimeout()},
	}
	for _, scope := range conf.Scope {
		switch scope {
		case "idcard", "smartid":
			c.addScope(scope, scope)
		case "mid":
			c.addScope(scope, "mID") // scope != AMR for mid.
		default:
			return nil, errors.Errorf("disallowed scope: %s", scope)
		}
	}

	ctx := oidc.ClientContext(context.Background(), c.http)
	vconf := oidc.Config{
		ClientID: conf.ClientIdentifier,
		SupportedSigningAlgs: []string{
			// Although TARA uses RS256 at the moment, future-proof
			// by supporting all algorithms provided by go-oidc.
			oidc.RS256, oidc.RS384, oidc.RS512,
			oidc.ES256, oidc.ES384, oidc.ES512,
			oidc.PS256, oidc.PS384, oidc.PS512,
		},
	}
	if conf.shouldDiscover() {
		c.logf("discovering configuration for issuer %s", conf.Issuer)
		provider, err := oidc.NewProvider(ctx, conf.Issuer)
		if err != nil {
			return nil, errors.Wrap(err, "autoconfigure provider")
		}
		c.oauth.Endpoint = provider.Endpoint() // Overwrite empty URLs.
		// No access to the discovered JWKS URL.
		c.logf("discovered configuration, AuthorizationEndpoint: %s, TokenEndpoint: %s",
			c.oauth.Endpoint.AuthURL, c.oauth.Endpoint.TokenURL)

		c.verifier = provider.Verifier(&vconf)
	} else {
		keyset := oidc.NewRemoteKeySet(ctx, conf.JWKSURI)
		c.verifier = oidc.NewVerifier(conf.Issuer, keyset, &vconf)
	}

	c.oauth.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return c, nil
}

func (c *client) addScope(scope, amr string) {
	if _, ok := c.amr[amr]; !ok {
		c.oauth.Scopes = append(c.oauth.Scopes, scope)
		c.amr[amr] = struct{}{}
	}
}

// AuthenticationRequest implements the tara.Client interface.
func (c *client) AuthenticationRequest(w http.ResponseWriter) error {
	state, err := c.addSecretCookie(w, c.conf.stateCookie())
	if err != nil {
		return errors.WithMessage(err, "create state")
	}
	nonce, err := c.addSecretCookie(w, c.conf.nonceCookie())
	if err != nil {
		w.Header().Del("Set-Cookie") // Remove all set cookies: hopefully only state.
		return errors.WithMessage(err, "create nonce")
	}

	location := c.oauth.AuthCodeURL(encodeSHA256(state), oidc.Nonce(encodeSHA256(nonce)))
	c.logf("redirecting to %s", location) // No secret cookies in log.

	// Manual redirect instead of http.Redirect - original request not
	// available and HTML body not required.
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
	return nil
}

func (c *client) addSecretCookie(w http.ResponseWriter, name string) (value string, err error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", errors.Wrap(err, "read random")
	}
	value = encode(secret)
	c.setCookie(w, name, value, 0)
	return value, nil
}

// AuthenticationResponse implements the tara.Client interface.
func (c *client) AuthenticationResponse(r *http.Request) (session.UserData, error) {
	// Although this information was likely already logged by HTTPS
	// filters, log it separately for TARA auditability purposes.
	c.logf("received authentication response, host: %s, uri: %s", r.Host, r.RequestURI)

	// Check for forged requests.
	query := r.URL.Query()
	state := query.Get("state")
	if state == "" {
		return session.UserData{}, BadRequestError{errors.New("missing state value")}
	}
	cookie, err := r.Cookie(c.conf.stateCookie())
	if err != nil {
		return session.UserData{}, BadRequestError{errors.New("missing state cookie")}
	}
	if expected := encodeSHA256(cookie.Value); state != expected {
		c.securityf("attempted CSRF? state: %s, expected: %s", state, expected)
		return session.UserData{}, BadRequestError{errors.New("state does not match")}
	}

	// Check for failed authentication.
	if errorCode := query.Get("error"); errorCode != "" {
		return session.UserData{}, errors.Errorf("authentication failed (%s): %s",
			errorCode, query.Get("error_description"))
	}

	// Exchange authorization code for token containing user data.
	code := r.URL.Query().Get("code")
	if code == "" {
		return session.UserData{}, BadRequestError{errors.New("missing authorization code")}
	}
	if cookie, err = r.Cookie(c.conf.nonceCookie()); err != nil {
		return session.UserData{}, BadRequestError{errors.New("missing nonce cookie")}
	}
	return c.tokenRequest(code, cookie.Value)
}

type claims struct {
	Profile struct {
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	} `json:"profile_attributes"`
	AMR       []string `json:"amr"`
	NotBefore int64    `json:"nbf"`
}

// tokenRequest requests user data from the token endpoint.
func (c *client) tokenRequest(code, nonce string) (session.UserData, error) {
	ctx := oidc.ClientContext(context.Background(), c.http)

	// Get token.
	c.logf("requesting token with code %s", code)
	token, err := c.oauth.Exchange(ctx, code)
	if err != nil {
		return session.UserData{}, errors.Wrap(err, "token request")
	}
	c.logf("received token: %+v", token)

	// Verify token.
	if tokenType := token.Type(); tokenType != "Bearer" {
		return session.UserData{}, errors.Errorf("unsupported token type: %s", tokenType)
	}
	idTokenJWT, ok := token.Extra("id_token").(string)
	if !ok {
		return session.UserData{}, errors.New("missing id_token")
	}
	c.logf("identity token: %s", idTokenJWT)

	idToken, err := c.verifier.Verify(ctx, idTokenJWT)
	if err != nil {
		return session.UserData{}, errors.Wrap(err, "verify token")
	}
	if expected := encodeSHA256(nonce); idToken.Nonce != expected {
		c.securityf("attempted replay attack? nonce: %s, expected %s", nonce, expected)
		return session.UserData{}, BadRequestError{errors.New("nonce does not match")}
	}

	// Extract claims and perform additional checks.
	var claims claims
	if err := idToken.Claims(&claims); err != nil {
		return session.UserData{}, errors.Wrap(err, "parse claims")
	}

	// NotBefore (nbf) is not used by OpenID Connect, but included by TARA
	// and MUST be checked separately.
	nbf := time.Unix(claims.NotBefore, 0)
	if time.Now().Before(nbf) {
		return session.UserData{}, errors.Errorf("token is not valid yet: not before %s", nbf)
	}

	if len(claims.AMR) != 1 {
		return session.UserData{}, errors.Errorf("AMR length not 1: %d", len(claims.AMR))
	}
	amr := claims.AMR[0]
	if _, ok := c.amr[amr]; !ok {
		c.securityf("attempted downgrade attack? AMR: %s, scopes: %s", amr, c.oauth.Scopes)
		return session.UserData{}, errors.Errorf(
			"authentication method %s not allowed", amr)
	}

	return session.UserData{
		UserRef: session.UserRef{
			Provider: session.TARA,
			UserID:   idToken.Subject,
		},
		FirstName: claims.Profile.GivenName,
		LastName:  claims.Profile.FamilyName,
	}, nil
}

// ClearCookies implements the tara.Client interface.
func (c *client) ClearCookies(w http.ResponseWriter) {
	c.setCookie(w, c.conf.stateCookie(), "", -1)
	c.setCookie(w, c.conf.nonceCookie(), "", -1)
}

func (c *client) setCookie(w http.ResponseWriter, name, value string, maxage int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     c.cookiePath,
		MaxAge:   maxage,
		Secure:   true,
		HttpOnly: true,
	})
}

func (c *client) logf(format string, v ...interface{}) {
	if c.conf.RequestLogger != nil {
		c.conf.RequestLogger.Printf(format+"\n", v...)
	}
}

func (c *client) securityf(format string, v ...interface{}) {
	if c.conf.SecurityLogger != nil {
		c.conf.SecurityLogger.Printf(format+"\n", v...)
	} else {
		c.logf(format, v...)
	}
}

func encodeSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return encode(hash[:])
}

func encode(data []byte) string {
	// RawURLEncoding avoids + and / (replaced with - and _) and the =
	// padding character (no need for it).
	return base64.RawURLEncoding.EncodeToString(data)
}
