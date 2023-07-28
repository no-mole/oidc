package oidc

type Storage interface {
	GetClientByClientId(clientId string) Client
	GenAuthorizationCode(client Client, userId string) (string, error)
	DecodeAuthCode(code string) (*AuthCodeInfo, error)
	ValidateAuthorizationCode(code, clientId string) bool
	GenToken(grantType GrantType, client Client, userId string, scopes []string, nonce, display, prompt, uiLocales, idTokenHint, loginHint, acrValues string, maxAge int64) (*TokenInfo, error)
	DecodeAccessTokenToUserId(accessToken string) (string, error)
	ValidateAccessToken(accessToken string, client Client) (bool, error)
	SaveToken(userId string, token *TokenInfo) error
	GetTokenByUserId(userId string) *TokenInfo
	SetUserInfo(info *UserInfo, userId string, scopes []string) error
	UserStorage
}

type TokenInfo struct {
	TokenType    string   `json:"token_type"`
	AccessToken  string   `json:"access_token"`
	IdToken      string   `json:"id_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int64    `json:"expires_in"`
	Scopes       []string `json:"scopes"`
	CreateTime   string   `json:"create_time"`
}

type AuthCodeInfo struct {
	ClientId   string `json:"client_id"`
	UserId     string `json:"user_id"`
	ExpiresIn  int64  `json:"expires_in"`
	CreateTime string `json:"create_time"`
}
