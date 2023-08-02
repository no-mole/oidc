package oidc

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

type EndSessionParams struct {
	ClientId              string `json:"client_id" form:"client_id"`
	IdTokenHint           string `json:"id_token_hint" form:"id_token_hint"`
	PostLogoutRedirectUri string `json:"post_logout_redirect_uri" form:"post_logout_redirect_uri"`
}

func EndSession(ctx *gin.Context, storage Storage) {
	p := &EndSessionParams{}
	err := ctx.ShouldBindJSON(p)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorInvalidRequest)
		return
	}
	claims, err := storage.DecodeIdToken(p.IdTokenHint)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%s,err:%s", ErrorServer, err.Error()))
		return
	}
	if p.ClientId != "" && p.ClientId != claims.AuthorizedParty {
		ctx.JSON(http.StatusBadRequest, errors.New("client_id does not match azp of id_token_hint"))
		return
	}
	err = storage.TerminateSession(claims.Subject, claims.Subject)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, fmt.Sprintf("%s,err:%s", ErrorServer, err.Error()))
		return
	}
	ctx.Redirect(http.StatusFound, p.PostLogoutRedirectUri)
	return
}
