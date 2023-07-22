package oidc

type Storage interface {
	GetClientByClientId(clientId string) (Client, error)
	GenAuthorizationCode(client Client, user *User) (*AuthCodeInfo, error)
	EncryptCode(authCodeInfo *AuthCodeInfo) string
	DecryptCode(code string) *AuthCodeInfo
	ValidateAuthorizationCode(code, clientId string) bool
	GenToken(client Client, user *User) (*TokenInfo, error)
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
	UserInfo   *User  `json:"user_info"`
	ClientId   string `json:"client_id"`
	ExpiresIn  int64  `json:"expires_in"`
	CreateTime string `json:"create_time"`
}

type UserStorage interface {
	GetUserByUserId(id int64) *User
	GetUserByUserName(userName string) *User
	GetUserByEmail(email string) *User
	GetUserByPhone(phone string) *User
}

type User struct {
	Id                    int64  `json:"id"`
	UserName              string `json:"name"`
	Email                 string `json:"email"`
	Password              string `json:"password"`
	Phone                 string `json:"phone"`
	IdSource              string `json:"id_source"`
	IsForceChangePassword bool   `json:"is_force_change_password"`
	IsDisabled            bool   `json:"is_disabled"`
	CreateTime            string `json:"create_time"`
}
