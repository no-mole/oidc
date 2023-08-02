package op

type Key interface {
	ID() string
	Algorithm() string
	Use() string
	Key() interface{}
}
