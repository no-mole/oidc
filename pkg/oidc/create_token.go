package oidc

import "time"

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
		Scopes:       scopes,
		CreateTime:   time.Now().Format(time.DateTime),
	}, nil
}

func CreateIdToken(storage Storage, client Client, p *TokenParams) (string, error) {
	idToken, err := storage.CreateIdToken(client, p.UserId, p.Nonce, p.Display, p.Prompt, p.UiLocales, p.IdTokenHint, p.LoginHint, p.AcrValues, p.MaxAge)
	if err != nil {
		return "", err
	}
	return idToken, nil
}

type TokenInfoResponse struct {
	TokenType    string   `json:"token_type"`
	AccessToken  string   `json:"access_token"`
	IdToken      string   `json:"id_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
	Scopes       []string `json:"scopes"`
	CreateTime   string   `json:"create_time"`
}
