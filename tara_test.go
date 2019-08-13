package tara

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// testClient unable to make OpenID Connect requests, but can be used to test
// authorization request URL's and response parameters.
var testClient = &client{
	oauth: oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://localhost/oidc/authorize",
			TokenURL: "https://localhost/oidc/token",
		},
		RedirectURL: "https://localhost/oidc/redirect",
		Scopes:      []string{oidc.ScopeOpenID, "idcard", "mid"},
	},
}

func TestClientAuthenticationRequest_TestData_CorrectRedirect(t *testing.T) {
	rr := httptest.NewRecorder()
	err := testClient.AuthenticationRequest(rr)
	if err != nil {
		t.Fatal(err)
	}
	resp := rr.Result()

	// Check that the user-agent is redirected.
	if resp.StatusCode != http.StatusFound {
		t.Errorf("unexpected status: got %d, expected %d",
			resp.StatusCode, http.StatusFound)
	}

	// Check that the state cookie is set.
	state, secure, httpOnly := getCookie(resp, DefaultStateCookie)
	if state == "" {
		t.Error("missing state cookie")
	}
	if !secure || !httpOnly {
		t.Error("state cookie is not Secure and HttpOnly")
	}

	// Check that the nonce cookie is set.
	nonce, secure, httpOnly := getCookie(resp, DefaultNonceCookie)
	if nonce == "" {
		t.Error("missing nonce cookie")
	}
	if !secure || !httpOnly {
		t.Error("nonce cookie is not Secure and HttpOnly")
	}

	// Check that the authentication request matches our expectations.
	expected := testClient.oauth.Endpoint.AuthURL +
		"?client_id=" + testClient.oauth.ClientID +
		"&nonce=" + encodeSHA256(nonce) +
		"&redirect_uri=" + url.QueryEscape(testClient.oauth.RedirectURL) +
		"&response_type=code" +
		"&scope=openid+idcard+mid" +
		"&state=" + encodeSHA256(state)

	location, err := resp.Location()
	if err != nil {
		t.Fatal("bad redirect location:", err)
	}
	if location.String() != expected {
		t.Errorf("unexpected authentication request,\nlocation: %s\nexpected: %s",
			location, expected)
	}
}

func getCookie(resp *http.Response, name string) (value string, secure, httpOnly bool) {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie.Value, cookie.Secure, cookie.HttpOnly
		}
	}
	return "", false, false
}

func TestClientAuthenticationResponse_MissingStateValue_ReturnsBadRequestError(t *testing.T) {
	testBadRequestError(t, "?code=code", "state", "nonce")
}

func TestClientAuthenticationResponse_MissingStateCookie_ReturnsBadRequestError(t *testing.T) {
	testBadRequestError(t, "?state="+encodeSHA256("")+"&code=code", "", "nonce")
}

func TestClientAuthenticationResponse_MismatchedState_ReturnsBadRequestError(t *testing.T) {
	testBadRequestError(t, "?state="+encodeSHA256("state1")+"&code=code", "state2", "nonce")
}

func TestClientAuthenticationResponse_MissingCodeValue_ReturnsBadRequestError(t *testing.T) {
	testBadRequestError(t, "?state="+encodeSHA256("state"), "state", "nonce")
}

func TestClientAuthenticationResponse_MissingNonceCookie_ReturnsBadRequestError(t *testing.T) {
	testBadRequestError(t, "?state="+encodeSHA256("state")+"&code=code", "state", "")
}

func testBadRequestError(t *testing.T, query, state, nonce string) {
	t.Helper()
	r := testAuthResponse(query, state, nonce)
	_, err := testClient.AuthenticationResponse(r)
	if err == nil {
		t.Fatal("unexpected success")
	}
	if _, ok := err.(BadRequestError); !ok {
		t.Error("unexpected non-BadRequestError:", err)
	}
}

func TestClientAuthenticationResponse_AuthenticationError_ReturnsError(t *testing.T) {
	query := "?state=" + encodeSHA256("state") +
		"&error=invalid_scope" +
		"&error_description=required+scope+not+provided"
	r := testAuthResponse(query, "state", "nonce")
	_, err := testClient.AuthenticationResponse(r)
	if err == nil {
		t.Fatal("unexpected success")
	}
	if _, ok := err.(BadRequestError); ok {
		t.Error("unexpected BadRequestError:", err)
	}
}

func testAuthResponse(query, state, nonce string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, testClient.oauth.RedirectURL+query, nil)
	if state != "" {
		r.AddCookie(&http.Cookie{Name: DefaultStateCookie, Value: state})
	}
	if nonce != "" {
		r.AddCookie(&http.Cookie{Name: DefaultNonceCookie, Value: nonce})
	}
	return r
}
