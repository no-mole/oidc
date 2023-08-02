package op

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func GetUserInfo(ctx *gin.Context, storage Storage) {
	accessToken, err := getAccessToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusForbidden, err)
		return
	}
	userId, err := storage.DecodeAccessTokenToUserId(accessToken)
	if err != nil {
		ctx.JSON(http.StatusForbidden, err)
		return
	}
	scopes := storage.GetTokenScopesByUserId(userId)
	userInfo := &UserInfo{}
	err = storage.SetUserInfo(userInfo, userId, scopes)
	if err != nil {
		ctx.JSON(http.StatusForbidden, err)
		return
	}
	ctx.JSON(http.StatusOK, userInfo)
}

func getAccessToken(ctx *gin.Context) (string, error) {
	authHeader := ctx.GetHeader("authorization")
	if authHeader == "" {
		return "", errors.New("no auth header")
	}
	parts := strings.Split(authHeader, "Bearer ")
	if len(parts) != 2 {
		return "", errors.New("invalid auth header")
	}
	return parts[1], nil
}
