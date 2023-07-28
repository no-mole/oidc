package oidc

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type GetUserInfoParams struct {
	ClientId string `json:"client_id" form:"client_id"`
}

func GetUserInfo(ctx *gin.Context, storage Storage) {
	p := &GetUserInfoParams{}
	err := ctx.ShouldBindQuery(p)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorInvalidRequest)
		return
	}
	client := storage.GetClientByClientId(p.ClientId)
	if client == nil || client.GetClientId() != p.ClientId {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), "", ErrorUnauthorizedClient, err.Error()))
		return
	}
	accessToken, err := getAccessToken(ctx)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), "", ErrorUnauthorizedClient, ""))
		return
	}
	if ok, err := storage.ValidateAccessToken(accessToken, client); !ok || err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), "", ErrorAccessDenied, ""))
		return
	}
	userId, err := storage.DecodeAccessTokenToUserId(accessToken)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), "", ErrorServer, ""))
		return
	}
	token := storage.GetTokenByUserId(userId)
	userInfo := &UserInfo{}
	err = storage.SetUserInfo(userInfo, userId, token.Scopes)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), "", ErrorServer, ""))
		return
	}
	ctx.JSON(200, userInfo)
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
