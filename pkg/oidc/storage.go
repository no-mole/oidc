package oidc

type Storage interface {
	GetClientByClientId(clientId string) Client
	GenAuthorizationCode(client Client, userId string) (string, error)
	DecodeAuthCode(code string) (*AuthCodeInfo, error)
	ValidateAuthorizationCode(code, clientId string) bool
	CreateIdToken(client Client, userId string, nonce, display, prompt, uiLocales, idTokenHint, loginHint, acrValues string, maxAge int64) (idToken string, err error)
	CreateAccessOrRefreshToken(grantType GrantType, client Client, needsRefreshToken bool, userId string, scopes []string) (accessToken, refreshToken string, expiresIn int64, err error)
	DecodeRefreshToken(refreshToken string) (clientId, userId string, err error)
	DecodeAccessTokenToUserId(accessToken string) (string, error)
	ValidateAccessToken(accessToken string, client Client) (bool, error)
	GetTokenScopesByUserId(userId string) []string
	SetUserInfo(info *UserInfo, userId string, scopes []string) error
	KeySet() ([]Key, error)
	UserStorage
}

type AuthCodeInfo struct {
	ClientId   string `json:"client_id"`
	UserId     string `json:"user_id"`
	ExpiresIn  int64  `json:"expires_in"`
	CreateTime string `json:"create_time"`
}
