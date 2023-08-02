package op

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func CodeExchange(ctx *gin.Context, p *TokenParams, client Client, storage Storage, scopes []string) {
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeCode) {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeCode, ErrorUnsupportedResponseType, fmt.Sprintf("client missing grant type %s", GrantTypeCode)))
		return
	}
	autoCodeInfo, err := storage.DecodeAuthCode(p.Code)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeCode, ErrorInvalidRequest, fmt.Sprintf("%s format error", p.Code)))
		return
	}
	if autoCodeInfo.ClientId == "" || autoCodeInfo.ClientId != client.GetClientId() || p.ClientSecret != client.GetClientSecret() {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeCode, ErrorAccessDenied, "code not match"))
		return
	}

	tokenResp, err := CreateAccessOrRefreshToken(storage, client, p, scopes)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeCode, ErrorServer, err.Error()))
		return
	}
	idToken, err := CreateIdToken(storage, client, p)
	if err != nil {
		ctx.Redirect(http.StatusFound, AuthErrorResponseURL(client.GetRedirectUri(), GrantTypeCode, ErrorServer, err.Error()))
		return
	}
	tokenResp.IdToken = idToken
	tokenResp.CreateTime = time.Now().Format(time.DateTime)
	ctx.JSON(http.StatusOK, tokenResp)
}
