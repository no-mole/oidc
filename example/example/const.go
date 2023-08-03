package example

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/no-mole/oidc/pkg/crypto"
)

var key = []byte("test")

func Encode(u interface{}) (string, error) {
	if u == nil {
		return "", errors.New("info is nil")
	}
	data, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	encrypted := crypto.Encrypt(data, key)
	if len(encrypted) == 0 {
		if err != nil {
			return "", errors.New("encode fail")
		}
	}
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func Decode(str string, dst interface{}) error {
	data, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	body := crypto.Decrypt(data, key)
	err = json.Unmarshal(body, dst)
	if err != nil {
		return err
	}
	return nil
}
