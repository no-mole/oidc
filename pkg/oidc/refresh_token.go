package oidc

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func RefreshToken(ctx *gin.Context, p *TokenParams, client Client, storage Storage, scopes []string) {
	if p.RefreshToken == "" {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeRefreshToken, ErrorInvalidRequest, ""))
		return
	}
	clientId, userId, err := storage.DecodeRefreshToken(p.RefreshToken)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeRefreshToken, ErrorInvalidRequest, "refresh_token invalid"))
		return
	}
	if p.ClientId != clientId || p.UserId != userId {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeRefreshToken, ErrorInvalidRequest, "refresh_token invalid"))
		return
	}
	tokenResp, err := CreateAccessOrRefreshToken(storage, client, p, scopes)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeRefreshToken, ErrorServer, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, tokenResp)
}
