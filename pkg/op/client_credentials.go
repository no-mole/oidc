package op

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func ClientCredentials(ctx *gin.Context, p *TokenParams, client Client, storage Storage, scopes []string) {
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeClientCredentials) {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeClientCredentials, ErrorUnsupportedResponseType, fmt.Sprintf("client missing grant type %s", GrantTypeCode)))
		return
	}
	if p.ClientSecret != client.GetClientSecret() {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeClientCredentials, ErrorAccessDenied, "wrong service user or password"))
	}
	tokenResp, err := CreateAccessOrRefreshToken(storage, client, p, scopes)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeClientCredentials, ErrorServer, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, tokenResp)
}
