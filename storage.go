package oidc

type Storage interface {
	GetClientByClientId(clientId string) (Client, error)
	GenAuthorizationCode(client Client) (string, error)
	DecodeAuthCode(code string) *AuthCodeInfo
	ValidateAuthorizationCode(code, clientId string) bool
	GenToken(client Client) (*TokenInfo, error)
	UserStorage
}

type TokenInfo struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	CreateTime   string `json:"create_time"`
}

type AuthCodeInfo struct {
	ClientId   string `json:"client_id"`
	ExpiresIn  int64  `json:"expires_in"`
	CreateTime string `json:"create_time"`
}

type UserStorage interface {
	GetUserName() string
}
