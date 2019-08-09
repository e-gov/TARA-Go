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
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"stash.ria.ee/vis3/vis3-common/pkg/confutil"
	"stash.ria.ee/vis3/vis3-common/pkg/log"
	"stash.ria.ee/vis3/vis3-sea/internal/session"
)

// DefaultHTTPTimeout is the default roundtrip timeout for requests sent to the
// OpenID Connect Provider.
const DefaultHTTPTimeout = 15 * time.Second

// Names of cookies used to store OpenID Connect request state and nonce.
const (
	stateCookie = "vis3-tara-state"
	nonceCookie = "vis3-tara-nonce"
)

// Client is a TARA client.
type Client interface {
	// AuthenticationRequest redirects the user-agent to send an
	// authentication request to the authorization endpoint.
	//
	// If the returned error is non-nil, then Client has not written
	// anything to w yet: the caller must report (and log) the error.
	AuthenticationRequest(context.Context, http.ResponseWriter) error

	// AuthenticationResponse handles a response from the authorization
	// endpoint (via user-agent redirect). If successful, it contacts the
	// token endpoint to obtain claims about the authenticated end-user.
	//
	// A returned BadRequestError indicates that r was invalid in some way.
	// Otherwise it was an internal server or TARA error.
	AuthenticationResponse(context.Context, *http.Request) (session.UserData, error)

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
	Issuer confutil.URL

	// AuthorizationEndpoint, TokenEndpoint, and JWKSURI specify
	// configuration information for the OpenID Connect Provider.
	//
	// If none of these values are specified, then OpenID Connect Discovery
	// is attempted with the Issuer Identifier to obtain the configuration.
	AuthorizationEndpoint confutil.URL
	TokenEndpoint         confutil.URL
	JWKSURI               confutil.URL

	RedirectionURI   confutil.URL // Redirection URI of the Relying Party.
	ClientIdentifier string       // Client Identifier of the Relying Party.
	ClientSecret     string       // Client Secret of the Relying Party.

	// Scope specifies additional scope values of the authorization
	// request. For TARA, this enumerates the allowed authentication
	// methods. Only "idcard", "mid", and "smartid" values are allowed.
	Scope []string

	// HTTPTimeout specifies the roundtrip timeout in seconds used for
	// HTTP requests sent to the OpenID Connect Provider. If unset, then
	// DefaultHTTPTimeout is used instead.
	HTTPTimeout confutil.Seconds `json:"HTTPTimeoutSeconds"`
}

func (c Conf) shouldDiscover() bool {
	return c.AuthorizationEndpoint.URL == nil &&
		c.TokenEndpoint.URL == nil &&
		c.JWKSURI.URL == nil
}

type client struct {
	cookiePath string
	amr        map[string]struct{} // Set of allowed authentication methods.
	verifier   *oidc.IDTokenVerifier
	oauth      oauth2.Config
	http       *http.Client // HTTP client used for all external requests.
}

// NewClient creates a new TARA client from the provided configuration.
func NewClient(conf Conf) (Client, error) {
	if conf.Issuer.URL == nil {
		return nil, errors.New("missing mandatory Issuer")
	}
	if conf.RedirectionURI.URL == nil {
		return nil, errors.New("missing mandatory Redirection URI")
	}
	c := &client{
		cookiePath: conf.RedirectionURI.URL.Path,
		amr:        make(map[string]struct{}),
		oauth: oauth2.Config{
			ClientID:     conf.ClientIdentifier,
			ClientSecret: conf.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  conf.AuthorizationEndpoint.Raw,
				TokenURL: conf.TokenEndpoint.Raw,
			},
			RedirectURL: conf.RedirectionURI.Raw,
			Scopes:      []string{oidc.ScopeOpenID},
		},
		http: &http.Client{Timeout: conf.HTTPTimeout.Or(DefaultHTTPTimeout)},
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
		log.Info().WithString("issuer", conf.Issuer).Log(ctx, "discovery")
		provider, err := oidc.NewProvider(ctx, conf.Issuer.Raw)
		if err != nil {
			return nil, errors.Wrap(err, "autoconfigure provider")
		}
		c.oauth.Endpoint = provider.Endpoint() // Overwrite empty URLs.
		log.Info().
			WithString("authURL", c.oauth.Endpoint.AuthURL).
			WithString("tokenURL", c.oauth.Endpoint.TokenURL).
			// No access to the discovered JWKS URL.
			Log(ctx, "configuration")

		c.verifier = provider.Verifier(&vconf)
	} else {
		keyset := oidc.NewRemoteKeySet(ctx, conf.JWKSURI.Raw)
		c.verifier = oidc.NewVerifier(conf.Issuer.Raw, keyset, &vconf)
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
func (c *client) AuthenticationRequest(ctx context.Context, w http.ResponseWriter) error {
	state, err := c.addSecretCookie(w, stateCookie)
	if err != nil {
		return errors.WithMessage(err, "create state")
	}
	nonce, err := c.addSecretCookie(w, nonceCookie)
	if err != nil {
		w.Header().Del("Set-Cookie") // Remove all set cookies: hopefully only state.
		return errors.WithMessage(err, "create nonce")
	}

	location := c.oauth.AuthCodeURL(encodeSHA256(state), oidc.Nonce(encodeSHA256(nonce)))
	log.Info().WithString("location", location).Log(ctx, "redirect") // No secret cookies in log.

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
func (c *client) AuthenticationResponse(ctx context.Context, r *http.Request) (session.UserData, error) {
	// Although this information was likely already logged by HTTPS
	// filters, log it separately for TARA auditability purposes.
	log.Info().WithString("host", r.Host).WithString("uri", r.RequestURI).Log(ctx, "redirect")

	// Check for forged requests.
	query := r.URL.Query()
	state := query.Get("state")
	if state == "" {
		return session.UserData{}, BadRequestError{errors.New("missing state value")}
	}
	cookie, err := r.Cookie(stateCookie)
	if err != nil {
		return session.UserData{}, BadRequestError{errors.New("missing state cookie")}
	}
	if expected := encodeSHA256(cookie.Value); state != expected {
		log.Security.Error().
			WithString("state", state).
			WithString("expected", expected).
			Log(ctx, "attempted_csrf?")
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
	if cookie, err = r.Cookie(nonceCookie); err != nil {
		return session.UserData{}, BadRequestError{errors.New("missing nonce cookie")}
	}
	return c.tokenRequest(ctx, code, cookie.Value)
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
func (c *client) tokenRequest(ctx context.Context, code, nonce string) (session.UserData, error) {
	ctx = oidc.ClientContext(ctx, c.http)

	// Get token.
	log.Info().WithString("code", code).Log(ctx, "request")
	token, err := c.oauth.Exchange(ctx, code)
	if err != nil {
		return session.UserData{}, errors.Wrap(err, "token request")
	}
	log.Info().WithJSON("token", token).Log(ctx, "response")

	// Verify token.
	if tokenType := token.Type(); tokenType != "Bearer" {
		return session.UserData{}, errors.Errorf("unsupported token type: %s", tokenType)
	}
	idTokenJWT, ok := token.Extra("id_token").(string)
	if !ok {
		return session.UserData{}, errors.New("missing id_token")
	}
	log.Info().WithJSON("jwt", idTokenJWT).Log(ctx, "id_token")

	idToken, err := c.verifier.Verify(ctx, idTokenJWT)
	if err != nil {
		return session.UserData{}, errors.Wrap(err, "verify token")
	}
	if expected := encodeSHA256(nonce); idToken.Nonce != expected {
		log.Security.Error().
			WithString("nonce", idToken.Nonce).
			WithString("expected", expected).
			Log(ctx, "attempted_replay?")
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
	log.Info().WithString("method", amr).Log(ctx, "amr")
	if _, ok := c.amr[amr]; !ok {
		log.Security.Error().
			WithString("amr", amr).
			WithString("scope", c.oauth.Scopes).
			Log(ctx, "attempted_downgrade?")
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
	c.setCookie(w, stateCookie, "", -1)
	c.setCookie(w, nonceCookie, "", -1)
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

func encodeSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return encode(hash[:])
}

func encode(data []byte) string {
	// RawURLEncoding avoids + and / (replaced with - and _) and the =
	// padding character (no need for it).
	return base64.RawURLEncoding.EncodeToString(data)
}
