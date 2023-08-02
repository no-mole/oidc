package oidc

type Key interface {
	ID() string
	Algorithm() string
	Use() string
	Key() interface{}
}
