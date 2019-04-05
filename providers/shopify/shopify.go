// Package shopify implements the OAuth2 protocol for authenticating users through shopify.
// This package can be used as a reference implementation of an OAuth2 provider for shopify.
package shopify

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"fmt"

	"github.com/jrbury/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      string = "https://%s.myshopify.com/admin/oauth/authorize"
	tokenURL     string = "https://%s.myshopify.com/admin/oauth/access_token"
	userEndpoint string = "https://%s.myshopify.com/admin/shop.json"
)

const (
	// ScopeProductsRead Access to Product, Product Variant, Product Image, Collect, Custom Collection, and Smart Collection.
	ScopeProductsRead string = "read_products"
	// ScopeOrdersRead Access to Order, Transaction and Fulfillment.
	ScopeOrdersRead string = "read_orders"
	// ScopeInventoryRead Access to Inventory Level and Inventory Item.
	ScopeInventoryRead string = "read_inventory"
	// ScopeLocationsRead Access to Inventory Level and Inventory Item.
	ScopeLocationsRead string = "read_locations"
)

// New creates a new Shopify provider, and sets up important connection details, such as shop name
// You should always call `shopify.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey string, secret string, callbackURL string, shopName string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		ShopName:     shopName,
		providerName: "shopify",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing shopify
type Provider struct {
	ClientKey    string
	Secret       string
	ShopName     string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name gets the name used to retrieve this provider.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns the underlying http client
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is no-op for the Shopify package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Shopify for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	s := &Session{
		AuthURL: url,
	}
	return s, nil
}

// FetchUser will go to Shopify and access basic info about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {

	s := session.(*Session)

	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", fmt.Sprintf(userEndpoint, p.ShopName), nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("X-Shopify-Access-Token", s.AccessToken)
	resp, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	err = userFromReader(resp.Body, &user)
	return user, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Nickname string `json:"shop_owner"`
		Location string `json:"province"`
		ID       int    `json:"id"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.Email = u.Email
	user.NickName = u.Nickname
	user.Location = u.Location
	user.UserID = strconv.Itoa(u.ID)

	return nil
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf(authURL, p.ShopName),
			TokenURL: fmt.Sprintf(tokenURL, p.ShopName),
		},
		Scopes: append([]string{}, scopes...),
	}

	return c
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
