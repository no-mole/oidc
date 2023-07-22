package oidc

type GrantType string

func ValidateGrantType(grantTypes []GrantType, grantType GrantType) bool {
	for _, item := range grantTypes {
		if item == grantType {
			return true
		}
	}
	return false
}

const (
	GrantTypeCode     = "authorization_code" // 授权码模式
	GrantTypeImplicit = "implicit"           // 隐式模式
)
