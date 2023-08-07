package oidc

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthorizeParams struct {
	ClientId    string    `json:"client_id" form:"client_id"`
	RedirectUri string    `json:"redirect_uri" form:"redirect_uri"`
	UserId      string    `json:"user_id" form:"user_id"`
	GrantType   GrantType `json:"grant_type" form:"grant_type"`
	Scopes      string    `json:"scopes" form:"scopes"`
	State       string    `json:"state" form:"state"`
	RequestId   string    `json:"request_id" form:"request_id"`
}

func Authorize(ctx *gin.Context, storage Storage) {
	p := &AuthorizeParams{}
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
	if !storage.CheckLogin(p.ClientId, p.RequestId) {
		// todo
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorInvalidRequest, err.Error()))
		return
	}
	switch p.GrantType {
	case GrantTypeCode:
		AuthorizationCode(ctx, p, client, storage)
		return
	case GrantTypeImplicit:
		Implicit(ctx, p, client, storage)
		return
	}
	ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), p.GrantType, ErrorInvalidRequest, fmt.Sprintf("%s not supported", p.GrantType)))
	return
}
