package oidc

import (
	"github.com/gin-gonic/gin"
)

type TokenParams struct {
	ClientId     string    `json:"client_id" form:"client_id"`
	ClientSecret string    `json:"client_secret" form:"client_secret"`
	GrantType    GrantType `json:"grant_type" form:"grant_type"`
	Code         string    `json:"code" form:"code"`
}

func AccessTokenByCode(ctx *gin.Context, storage Storage) {
	p := &TokenParams{}
	err := ctx.ShouldBindQuery(p)
	// todo
	if err != nil {
		return
	}
	client, err := storage.GetClientByClientId(p.ClientId)
	// todo
	if client == nil {
		return
	}
	// todo err
	if err != nil {
		return
	}
	if p.GrantType != GrantTypeCode {
		return
	}
	if !ValidateGrantType(client.GetGrantTypes(), GrantTypeCode) {
		return
	}
	autoCodeInfo := storage.DecodeAuthCode(p.Code)
	if autoCodeInfo.ClientId == "" || autoCodeInfo.ClientId != client.GetClientId() || p.ClientSecret != client.GetClientSecret() {
		return
	}
	// todo
	tokenInfo, err := storage.GenToken(client)
	// url := fmt.Sprintf("%s?access_token=%s&token_type=%s&expires_in=%d", client.GetRedirectUri(), tokenInfo.AccessToken, tokenInfo.TokenType, tokenInfo.ExpiresIn)
	//ctx.Redirect(http.StatusFound, url)
	ctx.JSON(200, tokenInfo)
}
