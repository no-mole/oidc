package op

type Client interface {
	GetClientId() string
	GetRedirectUri() string
	GetIsDisabled() bool
	GetGrantTypes() []GrantType
	GetClientSecret() string
}
