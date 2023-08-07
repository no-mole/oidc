package oidc

import (
	"strings"
	"time"
)

const Bearer = "bearer"

func CreateAccessOrRefreshToken(storage Storage, client Client, p *TokenParams, scopes []string) (*TokenInfoResponse, error) {
	needsRefreshToken := false
	if p.GrantType == GrantTypeCode || p.GrantType == GrantTypeRefreshToken {
		needsRefreshToken = true
	}
	accessToken, refreshToken, expiresIn, err := storage.CreateAccessOrRefreshToken(p.GrantType, client, needsRefreshToken, p.UserId, scopes)
	if err != nil {
		return nil, err
	}
	return &TokenInfoResponse{
		TokenType:    Bearer,
		AccessToken:  accessToken,
		IdToken:      "",
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		CreateTime:   time.Now().Format(time.DateTime),
	}, nil
}

func CreateIdToken(storage Storage, client Client, p *TokenParams) (string, error) {
	claims := NewIDTokenClaims(p.Issuer, client.GetClientId(), p.UserId, []string{client.GetClientId()}, p.Nonce, p.AcrValues, p.Amr)
	userInfo := &UserInfo{}
	var scopes []string
	if p.Scopes != "" {
		scopes = strings.Split(p.Scopes, " ")
	}
	err := storage.SetUserInfo(userInfo, p.UserId, scopes)
	if err != nil {
		return "", err
	}
	claims.UserInfoPhone = userInfo.UserInfoPhone
	claims.UserInfoProfile = userInfo.UserInfoProfile
	claims.UserInfoEmail = userInfo.UserInfoEmail
	idToken, err := storage.CreateIdToken(claims)
	if err != nil {
		return "", err
	}
	return idToken, nil
}

func NewIDTokenClaims(issuer, clientId, userId string, audience []string, nonce string, acr string, amr []string) *IdTokenClaims {
	audience = AppendClientIDToAudience(clientId, audience)
	return &IdTokenClaims{
		Issuer:                              issuer,
		Subject:                             userId,
		Audience:                            audience,
		Expiration:                          time.Now().Add(time.Hour),
		IssuedAt:                            time.Now(),
		AuthTime:                            time.Now(),
		Nonce:                               nonce,
		AuthenticationContextClassReference: acr,
		AuthenticationMethodsReferences:     amr,
		AuthorizedParty:                     clientId,
		ClientID:                            clientId,
	}
}

func AppendClientIDToAudience(clientID string, audience []string) []string {
	for _, aud := range audience {
		if aud == clientID {
			return audience
		}
	}
	return append(audience, clientID)
}

type TokenInfoResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	CreateTime   string `json:"create_time"`
}

type IdTokenClaims struct {
	Issuer                              string    `json:"iss,omitempty"`
	Subject                             string    `json:"sub,omitempty"`
	Audience                            []string  `json:"aud,omitempty"`
	Expiration                          time.Time `json:"exp,omitempty"`
	IssuedAt                            time.Time `json:"iat,omitempty"`
	AuthTime                            time.Time `json:"auth_time,omitempty"`
	Nonce                               string    `json:"nonce,omitempty"`
	AuthenticationContextClassReference string    `json:"acr,omitempty"`
	AuthenticationMethodsReferences     []string  `json:"amr,omitempty"`
	AuthorizedParty                     string    `json:"azp,omitempty"`
	ClientID                            string    `json:"client_id,omitempty"`
	UserInfoProfile
	UserInfoEmail
	UserInfoPhone
}
