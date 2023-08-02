package oidc

import (
	"errors"
	"fmt"
)

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
	GrantTypeRefreshToken      = "refresh_token"      // 刷新令牌
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

func ValidateClient(clientId, redirectUri string, storage Storage) (Client, error) {
	client := storage.GetClientByClientId(clientId)
	if client == nil || client.GetClientId() != clientId {
		return nil, errors.New(ErrorInvalidRequest)
	}
	if client.GetRedirectUri() != redirectUri {
		return nil, errors.New(ErrorInvalidRequest)
	}
	return client, nil
}
