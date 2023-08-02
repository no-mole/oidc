package example

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"oidc/pkg/oidc"
)

type signKey struct {
	id        string
	algorithm string
	key       *rsa.PrivateKey
}

func (s *signKey) ID() string {
	return s.id
}

func (s *signKey) Algorithm() string {
	return s.algorithm
}

func (s *signKey) Use() string {
	return "sig"
}

func (s *signKey) Key() interface{} {
	return &s.key.PublicKey
}

type idTokenClaims struct {
	*oidc.IdTokenClaims
	jwt.RegisteredClaims
}

func (s *signKey) Encrypt(p *oidc.IdTokenClaims) (string, error) {
	claims := &idTokenClaims{p, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(p.Expiration),
		NotBefore: nil,
		IssuedAt:  jwt.NewNumericDate(p.IssuedAt),
	}}
	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return idToken.SignedString(s.key)
}

func (s *signKey) Decrypt(idToken string) (*idTokenClaims, error) {
	token, err := jwt.ParseWithClaims(idToken, &idTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return &s.key.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*idTokenClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}
