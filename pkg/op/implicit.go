package op

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func Implicit(ctx *gin.Context, p *AuthorizeParams, client Client, storage Storage) {
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeImplicit) {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeImplicit, ErrorUnsupportedResponseType, ""))
		return
	}
	if p.Scopes == "" {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeImplicit, ErrorInvalidScope, "scopes not found"))
		return
	}
	scopes := strings.Split(p.Scopes, ",")
	accessToken, _, expiresIn, err := storage.CreateAccessOrRefreshToken(GrantTypeImplicit, client, false, p.UserId, scopes)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeImplicit, ErrorServer, err.Error()))
		return
	}
	url := fmt.Sprintf("%s?access_token=%s&token_type=%s&expires_in=%d", client.GetRedirectUri(), accessToken, Bearer, expiresIn)
	ctx.Redirect(http.StatusFound, url)
	return
}
