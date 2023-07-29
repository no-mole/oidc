package example

import (
	"crypto/rsa"
	"github.com/square/go-jose/v3"
)

type signKey struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

func (s *signKey) ID() string {
	return s.id
}

func (s *signKey) Algorithm() jose.SignatureAlgorithm {
	return s.algorithm
}

func (s *signKey) Use() string {
	return "sig"
}

func (s *signKey) Key() interface{} {
	return &s.key.PublicKey
}
