package op

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func PasswordCredentials(ctx *gin.Context, p *TokenParams, client Client, storage Storage, scopes []string) {
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypePassword) {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypePassword, ErrorUnsupportedResponseType, fmt.Sprintf("client missing grant type %s", GrantTypeCode)))
		return
	}
	if p.Password == "" || p.Username == "" || p.Password != storage.GetPassword(p.Username) {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypePassword, ErrorAccessDenied, "username & password match failed"))
		return
	}
	tokenResp, err := CreateAccessOrRefreshToken(storage, client, p, scopes)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypePassword, ErrorServer, err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, tokenResp)
}
