package oidc

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Authorize(ctx *gin.Context, storage Storage) {
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
	// todo
	if client.GetClientId() != clientId {
		return
	}
	redirectUri := ctx.Params.ByName("redirect_uri")
	// todo
	if client.GetRedirectUri() != redirectUri {
		return
	}
	// todo
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeCode) && !ValidateGrantType(client.GetGrantTypes(), GrantTypeImplicit) {
		return
	}
	grantType := ctx.Params.ByName("grant_type")
	if grantType == GrantTypeCode {
		code, err := storage.GenAuthorizationCode(client)
		// todo err
		if err != nil {
			return
		}
		url := fmt.Sprintf("%s?code=%s", client.GetRedirectUri(), code)
		ctx.Redirect(http.StatusFound, url)
		return
	}

	token, err := storage.GenToken(client)
	if err != nil {
		return
	}
	url := fmt.Sprintf("%s?access_token=%s&token_type=%s&expires_in=%d", client.GetRedirectUri(), token.AccessToken, token.TokenType, token.ExpiresIn)
	ctx.Redirect(http.StatusFound, url)
}
