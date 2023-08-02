package op

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func AuthorizationCode(ctx *gin.Context, p *AuthorizeParams, client Client, storage Storage) {
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeCode) {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeCode, ErrorUnsupportedResponseType, ""))
		return
	}
	code, err := storage.GenAuthorizationCode(client, p.UserId)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeCode, ErrorServer, err.Error()))
		return
	}
	ctx.Redirect(http.StatusFound, fmt.Sprintf("%s?code=%s", client.GetRedirectUri(), code))
	return
}
