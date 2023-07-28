package oidc

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type TokenParams struct {
	ClientId     string    `json:"client_id" form:"client_id"`
	ClientSecret string    `json:"client_secret" form:"client_secret"`
	UserId       string    `json:"user_id" form:"user_id"`
	GrantType    GrantType `json:"grant_type" form:"grant_type"`
	Code         string    `json:"code" form:"code"`
	Scopes       string    `json:"scopes" form:"scopes"`
	Username     string    `json:"username" form:"username"`
	Password     string    `json:"password" form:"password"`
	Nonce        string    `json:"nonce" form:"nonce"`
	Display      string    `json:"display" form:"display"`
	Prompt       string    `json:"prompt" form:"prompt"`
	UiLocales    string    `json:"ui_locales" form:"ui_locales"`
	IdTokenHint  string    `json:"id_token_hint" form:"id_token_hint"`
	LoginHint    string    `json:"login_hint" form:"login_hint"`
	AcrValues    string    `json:"acr_values" form:"acr_values"`
	MaxAge       int64     `json:"max_age" form:"max_age"`
}

func Token(ctx *gin.Context, storage Storage) {
	p := &TokenParams{}
	err := ctx.ShouldBindQuery(p)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorInvalidRequest)
		return
	}
	client := storage.GetClientByClientId(p.ClientId)
	if client == nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorUnauthorizedClient, ""))
		return
	}
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeCode) {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorUnsupportedResponseType, ""))
		return
	}
	if p.GrantType == GrantTypeCode {
		autoCodeInfo, err := storage.DecodeAuthCode(p.Code)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, ErrorInvalidRequest)
			return
		}
		if autoCodeInfo.ClientId == "" || autoCodeInfo.ClientId != client.GetClientId() || p.ClientSecret != client.GetClientSecret() {
			ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorAccessDenied, ""))
			return
		}
	}
	if p.GrantType == GrantTypePassword {
		if p.Password == "" || p.Username == "" || p.Password != storage.GetPassword(p.Username) {
			ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorAccessDenied, ""))
			return
		}
	}
	if p.Scopes == "" {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorInvalidScope, err.Error()))
		return
	}
	scopes := strings.Split(p.Scopes, ",")
	tokenInfo, err := storage.GenToken(p.GrantType, client, p.UserId, scopes, p.Nonce, p.Display, p.Prompt, p.UiLocales, p.IdTokenHint, p.LoginHint, p.AcrValues, p.MaxAge)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorServer, err.Error()))
		return
	}
	err = storage.SaveToken(p.UserId, tokenInfo)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorServer, err.Error()))
		return
	}
	ctx.JSON(200, tokenInfo)
}
