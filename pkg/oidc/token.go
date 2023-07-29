package oidc

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type TokenParams struct {
	ClientId     string    `json:"client_id" form:"client_id"`
	ClientSecret string    `json:"client_secret" form:"client_secret"`
	RedirectUri  string    `json:"redirect_uri" form:"redirect_uri"`
	UserId       string    `json:"user_id" form:"user_id"`
	GrantType    GrantType `json:"grant_type" form:"grant_type"`
	RefreshToken string    `json:"refresh_token" form:"refresh_token"`
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
	client, err := ValidateClient(p.ClientId, p.RedirectUri, storage)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorInvalidRequest, err.Error()))
		return
	}
	if p.Scopes == "" {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeCode, ErrorInvalidScope, err.Error()))
		return
	}
	scopes := strings.Split(p.Scopes, ",")
	switch p.GrantType {
	case GrantTypeCode:
		CodeExchange(ctx, p, client, storage, scopes)
		return
	case GrantTypePassword:
		PasswordCredentials(ctx, p, client, storage, scopes)
		return
	case GrantTypeClientCredentials:
		ClientCredentials(ctx, p, client, storage, scopes)
		return
	case GrantTypeRefreshToken:
		RefreshToken(ctx, p, client, storage, scopes)
		return
	}
	ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorInvalidRequest, fmt.Sprintf("%s not supported", p.GrantType)))
}
