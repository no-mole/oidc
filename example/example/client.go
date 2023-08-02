package example

import "oidc/pkg/op"

type Client struct {
	id          string
	secret      string
	redirectUri string
	grantTypes  []op.GrantType
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

func (c *Client) GetGrantTypes() []op.GrantType {
	return c.grantTypes
}

func (c *Client) GetClientSecret() string {
	return c.secret
}
