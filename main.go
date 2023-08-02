package main

import (
	"github.com/gin-gonic/gin"
	"oidc/pkg/oidc"
)

func Init(r *gin.Engine, storage oidc.Storage) {
	r.GET("/authorize", func(ctx *gin.Context) {
		oidc.Authorize(ctx, storage)
	})
	r.GET("/token", func(ctx *gin.Context) {
		oidc.Token(ctx, storage)
	})
}
