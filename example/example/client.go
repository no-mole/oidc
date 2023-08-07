package example

import "github.com/no-mole/oidc/pkg/oidc"

type Client struct {
	id          string
	secret      string
	redirectUri string
	grantTypes  []oidc.GrantType
	isDisabled  bool
}

func (c *Client) GetClientId() string {
	return c.id
}

func (c *Client) GetRedirectUri() string {
	return c.redirectUri
}

func (c *Client) GetIsDisabled() bool {
	return c.isDisabled
}

func (c *Client) GetGrantTypes() []oidc.GrantType {
	return c.grantTypes
}

func (c *Client) GetClientSecret() string {
	return c.secret
}
