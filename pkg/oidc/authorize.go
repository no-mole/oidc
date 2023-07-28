package oidc

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type AuthorizeParams struct {
	ClientId    string    `json:"client_id" form:"client_id"`
	RedirectUri string    `json:"redirect_uri" form:"redirect_uri"`
	UserId      string    `json:"user_id" form:"user_id"`
	GrantType   GrantType `json:"grant_type" form:"grant_type"`
	Scopes      string    `json:"scopes" form:"scopes"`
}

func Authorize(ctx *gin.Context, storage Storage) {
	p := &AuthorizeParams{}
	err := ctx.ShouldBindQuery(p)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorInvalidRequest)
		return
	}
	if p.ClientId == "" {
		ctx.JSON(http.StatusBadRequest, ErrorInvalidRequest)
		return
	}
	client := storage.GetClientByClientId(p.ClientId)
	if client == nil || client.GetClientId() != p.ClientId {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorUnauthorizedClient, err.Error()))
		return
	}
	if client.GetRedirectUri() != p.RedirectUri {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorInvalidRequest, ""))
		return
	}
	// todo
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeCode) && !ValidateGrantType(client.GetGrantTypes(), GrantTypeImplicit) {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorUnsupportedResponseType, ""))
		return
	}
	if p.UserId == "" {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorInvalidRequest, ""))
		return
	}
	if p.GrantType == GrantTypeCode {
		code, err := storage.GenAuthorizationCode(client, p.UserId)
		if err != nil {
			ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorServer, err.Error()))
			return
		}
		ctx.Redirect(http.StatusFound, fmt.Sprintf("%s?code=%s", client.GetRedirectUri(), code))
		return
	}
	if p.Scopes == "" {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorInvalidScope, err.Error()))
		return
	}
	scopes := strings.Split(p.Scopes, ",")
	token, err := storage.GenToken(p.GrantType, client, p.UserId, scopes, "", "", "", "", "", "", "", 0)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorServer, err.Error()))
		return
	}
	url := fmt.Sprintf("%s?access_token=%s&token_type=%s&expires_in=%d", client.GetRedirectUri(), token.AccessToken, token.TokenType, token.ExpiresIn)
	ctx.Redirect(http.StatusFound, url)
	return
}
