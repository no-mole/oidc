package oidc

import "fmt"

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
	GrantTypeCode              = "authorization_code" // 授权码模式
	GrantTypeImplicit          = "implicit"           // 隐式模式
	GrantTypePassword          = "password"           // 资源所有者密码凭证许可
	GrantTypeClientCredentials = "client_credentials" // 客户端凭据许可
)

func AuthErrorResponseURL(redirectUri string, grantType GrantType, errType, errorDescription string) string {
	return fmt.Sprintf("%s?grant_type=%s&err_type=%s&err_desc=%s", redirectUri, grantType, errType, errorDescription)
}

const (
	ScopeOpenID = "openid"

	ScopeProfile = "profile"

	ScopeEmail = "email"

	ScopeAddress = "address"

	ScopePhone = "phone"
)
