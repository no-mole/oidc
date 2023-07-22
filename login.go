package oidc

import "github.com/gin-gonic/gin"

type LoginParams struct {
	UserName  string
	Email     string
	Phone     string
	Password  string
	LoginType string
}

const (
	LoginEmail    = "email"
	LoginPassword = "password"
	LoginPhone    = "phone"
)

func Login(ctx *gin.Context, storage Storage) {
	p := &LoginParams{}
	err := ctx.ShouldBindJSON(p)
	// todo err
	if err != nil {
		return
	}
	user := &User{}
	switch p.LoginType {
	case LoginEmail:
		user = storage.GetUserByEmail(p.Email)
	case LoginPassword:
		user = storage.GetUserByUserName(p.UserName)
	case LoginPhone:
		user = storage.GetUserByPhone(p.Phone)
	}
	// todo
	if p.Password != user.Password {
		return
	}
}
