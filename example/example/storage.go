package example

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"oidc/pkg/op"
	"sync"
	"time"
)

type Storage struct {
	lock          sync.Mutex
	clients       map[string]*Client
	codes         map[string]string
	tokens        map[string]*Token
	refreshTokens map[string]*Token
	key           signKey
	UserStorage
}

type Token struct {
	UserId    string
	Username  string
	ClientId  string
	TokenType string
	GrantType op.GrantType
	Scopes    []string
	ExpireIn  int64
	CreateAt  string
}

const (
	TokenTypeAccess  = "access_token"
	TokenTypeRefresh = "refresh_token"
)

func (s *Storage) GetClientByClientId(clientId string) op.Client {
	return s.clients[clientId]
}

func (s *Storage) GenAuthorizationCode(client op.Client, userId string) (string, error) {
	authCodeInfo := &op.AuthCodeInfo{
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

func (s *Storage) DecodeAuthCode(code string) (*op.AuthCodeInfo, error) {
	data, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return nil, err
	}
	authCodeInfo := &op.AuthCodeInfo{}
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

func (s *Storage) CreateAccessOrRefreshToken(grantType op.GrantType, client op.Client, needsRefreshToken bool, userId string, scopes []string) (accessToken, refreshToken string, expiresIn int64, err error) {
	user := s.UserStorage.GetUserByUserId(userId)
	if user == nil {
		return "", "", 0, errors.New("user not found")
	}
	token := &Token{
		UserId:    userId,
		Username:  user.Username,
		ClientId:  client.GetClientId(),
		GrantType: grantType,
		Scopes:    scopes,
		ExpireIn:  3600,
		CreateAt:  time.Now().Format(time.DateTime),
	}
	// accessToken
	token.TokenType = TokenTypeAccess
	accessToken, err = Encode(token)
	s.tokens[userId] = token
	if err != nil {
		return "", "", 0, err
	}
	// refreshToken
	if needsRefreshToken {
		token.TokenType = TokenTypeRefresh
		refreshToken, err = Encode(token)
		s.refreshTokens[userId] = token
		if err != nil {
			return "", "", 0, err
		}
	}
	return accessToken, refreshToken, token.ExpireIn, nil
}

func (s *Storage) CreateIdToken(claims *op.IdTokenClaims) (string, error) {
	return s.key.Encrypt(claims)
}

func (s *Storage) DecodeIdToken(idToken string) (claims *op.IdTokenClaims, err error) {
	idc, err := s.key.Decrypt(idToken)
	if err != nil {
		return nil, err
	}
	return idc.IdTokenClaims, nil
}

func (s *Storage) ValidateAccessToken(accessToken string, client op.Client) (bool, error) {
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

func (s *Storage) DecodeRefreshToken(refreshToken string) (clientId, userId string, err error) {
	token := &Token{}
	err = Decode(refreshToken, token)
	if err != nil {
		return "", "", err
	}
	return token.ClientId, token.UserId, nil
}

func (s *Storage) SetUserInfo(info *op.UserInfo, userId string, scopes []string) error {
	user := s.UserStorage.GetUserByUserId(userId)
	if user == nil {
		return errors.New("user not found")
	}
	for _, scope := range scopes {
		switch scope {
		case op.ScopeOpenID:
			info.Subject = user.ID
		case op.ScopeEmail:
			info.Email = user.Email
			info.EmailVerified = user.EmailVerified
		case op.ScopeProfile:
			info.PreferredUsername = user.Username
			info.Name = user.FirstName + " " + user.LastName
			info.FamilyName = user.LastName
			info.GivenName = user.FirstName
			info.Locale = user.PreferredLanguage
		case op.ScopePhone:
			info.PhoneNumber = user.Phone
			info.PhoneNumberVerified = user.PhoneVerified
		}
	}
	info.Email = user.Email
	return nil
}

func (s *Storage) GetTokenScopesByUserId(userId string) []string {
	return s.tokens[userId].Scopes
}

func (s *Storage) KeySet() ([]op.Key, error) {
	return []op.Key{&s.key}, nil
}

func (s *Storage) TerminateSession(clientId, userId string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, token := range s.tokens {
		if token.ClientId == clientId && token.UserId == userId {
			delete(s.tokens, userId)
			delete(s.refreshTokens, userId)
		}
	}
	return nil
}

func NewStorage(storage UserStorage) *Storage {
	rasKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &Storage{
		clients: map[string]*Client{
			"test": {
				id:          "test",
				secret:      "testsecret",
				redirectUri: "http://localhost:9998/hello",
				grantTypes:  []op.GrantType{op.GrantTypeCode, op.GrantTypeImplicit, op.GrantTypePassword},
				isDisabled:  false,
			},
		},
		codes:         make(map[string]string),
		tokens:        make(map[string]*Token),
		refreshTokens: make(map[string]*Token),
		UserStorage:   storage,
		key: signKey{
			id:        uuid.NewString(),
			algorithm: jwt.SigningMethodRS256.Alg(),
			key:       rasKey,
		},
	}
}