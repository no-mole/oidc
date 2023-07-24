package oidc

type Client interface {
	GetClientId() string
	GetRedirectUri() string
	GetGrantTypes() []GrantType
	GetClientSecret() string
}
