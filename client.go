package oidc

type Client interface {
	GetId() string
	GetRedirectUri() string
	GetGrantTypes() []GrantType
	GetClientSecret() string
}
