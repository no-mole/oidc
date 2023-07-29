package oidc

import (
	"github.com/square/go-jose/v3"
)

type Key interface {
	ID() string
	Algorithm() jose.SignatureAlgorithm
	Use() string
	Key() interface{}
}
