package example

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"oidc/pkg/oidc"
	"time"
)

type Storage struct {
	clients map[string]*Client
	codes   map[string]string
	tokens  map[string]*oidc.TokenInfo
	UserStorage
}

type Token struct {
	UserId    string
	Username  string
	ClientId  string
	TokenType string
	GrantType oidc.GrantType
	ExpireIn  int64
	CreateAt  string
}

const (
	TokenTypeAccess  = "access_token"
	TokenTypeRefresh = "refresh_token"
)

func (s *Storage) GetClientByClientId(clientId string) oidc.Client {
	return s.clients[clientId]
}

func (s *Storage) GenAuthorizationCode(client oidc.Client, userId string) (string, error) {
	authCodeInfo := &oidc.AuthCodeInfo{
		ClientId:   client.GetClientId(),
		UserId:     userId,
		ExpiresIn:  3600,
		CreateTime: time.Now().Format(time.DateTime),
	}
	data, err := json.Marshal(authCodeInfo)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (s *Storage) DecodeAuthCode(code string) (*oidc.AuthCodeInfo, error) {
	data, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return nil, err
	}
	authCodeInfo := &oidc.AuthCodeInfo{}
	err = json.Unmarshal(data, authCodeInfo)
	if err != nil {
		return nil, err
	}
	return authCodeInfo, nil
}

func (s *Storage) ValidateAuthorizationCode(code, clientId string) bool {
	authCodeInfo, err := s.DecodeAuthCode(code)
	if err != nil {
		return false
	}
	return authCodeInfo.ClientId == clientId
}

func (s *Storage) GenToken(grantType oidc.GrantType, client oidc.Client, userId string, scopes []string, nonce, display, prompt, uiLocales, idTokenHint, loginHint, acrValues string, maxAge int64) (*oidc.TokenInfo, error) {
	user := s.UserStorage.GetUserByUserId(userId)
	if user == nil {
		return nil, errors.New("user not found")
	}
	var err error
	token := &Token{
		UserId:    userId,
		Username:  user.Username,
		ClientId:  client.GetClientId(),
		GrantType: grantType,
		ExpireIn:  3600,
		CreateAt:  time.Now().Format(time.DateTime),
	}
	tokenInfo := &oidc.TokenInfo{
		TokenType:  string(grantType),
		ExpiresIn:  3600,
		CreateTime: time.Now().Format(time.DateTime),
		Scopes:     scopes,
	}
	token.TokenType = TokenTypeAccess
	tokenInfo.AccessToken, err = Encode(token)
	if err != nil {
		return nil, err
	}
	token.TokenType = TokenTypeRefresh
	tokenInfo.RefreshToken, err = Encode(token)
	if err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

func (s *Storage) ValidateAccessToken(accessToken string, client oidc.Client) (bool, error) {
	token := &Token{}
	err := Decode(accessToken, token)
	if err != nil {
		return false, err
	}
	if token.ClientId != client.GetClientId() {
		return false, errors.New("clientId not match")
	}
	if token.UserId == "" && token.ClientId == "" && token.Username == "" {
		return false, errors.New("invalid user or client token")
	}
	createAt, err := time.Parse(time.DateTime, token.CreateAt)
	if err != nil {
		return false, errors.New("token expired")
	}
	if int64(time.Since(createAt).Seconds()) > token.ExpireIn {
		return false, errors.New("token expired")
	}
	return true, nil
}

func (s *Storage) DecodeAccessTokenToUserId(accessToken string) (string, error) {
	token := &Token{}
	err := Decode(accessToken, token)
	if err != nil {
		return "", err
	}
	return token.UserId, err
}

func (s *Storage) SaveToken(userId string, token *oidc.TokenInfo) error {
	s.tokens[userId] = token
	return nil
}

func (s *Storage) SetUserInfo(info *oidc.UserInfo, userId string, scopes []string) error {
	user := s.UserStorage.GetUserByUserId(userId)
	if user == nil {
		return errors.New("user not found")
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			info.Subject = user.ID
		case oidc.ScopeEmail:
			info.Email = user.Email
			info.EmailVerified = user.EmailVerified
		case oidc.ScopeProfile:
			info.PreferredUsername = user.Username
			info.Name = user.FirstName + " " + user.LastName
			info.FamilyName = user.LastName
			info.GivenName = user.FirstName
			info.Locale = user.PreferredLanguage
		case oidc.ScopePhone:
			info.PhoneNumber = user.Phone
			info.PhoneNumberVerified = user.PhoneVerified
		}
	}
	info.Email = user.Email
	return nil
}

func (s *Storage) GetTokenByUserId(userId string) *oidc.TokenInfo {
	return s.tokens[userId]
}

func NewStorage(storage UserStorage) *Storage {
	return &Storage{
		clients: map[string]*Client{
			"test": {
				id:          "test",
				secret:      "testsecret",
				redirectUri: "http://localhost:9998/hello",
				grantTypes:  []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeImplicit, oidc.GrantTypePassword},
				isDisabled:  false,
			},
		},
		codes:       make(map[string]string),
		tokens:      make(map[string]*oidc.TokenInfo),
		UserStorage: storage,
	}
}
