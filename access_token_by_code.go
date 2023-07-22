package oidc

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func AccessTokenByCode(ctx *gin.Context, storage Storage) {
	clientId := ctx.Params.ByName("client_id")
	client, err := storage.GetClientByClientId(clientId)
	// todo
	if client == nil {
		return
	}
	// todo err
	if err != nil {
		return
	}
	grantType := ctx.Params.ByName("grant_type")
	if grantType != GrantTypeCode {
		return
	}
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeCode) {
		return
	}
	code := ctx.Params.ByName("code")
	autoCodeInfo := storage.DecryptCode(code)
	if autoCodeInfo.ClientId != clientId {
		return
	}
	// todo
	tokenInfo, err := storage.GenToken(client, autoCodeInfo.UserInfo)
	url := fmt.Sprintf("%s?access_token=%s&token_type=%s&expires_in=%d", client.GetRedirectUri(), tokenInfo.AccessToken, tokenInfo.TokenType, tokenInfo.ExpiresIn)
	ctx.Redirect(http.StatusFound, url)
}
