package main

import (
	"github.com/gin-gonic/gin"
	"oidc/pkg/op"
)

func Init(r *gin.Engine, storage op.Storage) {
	r.GET("/authorize", func(ctx *gin.Context) {
		op.Authorize(ctx, storage)
	})
	r.GET("/token", func(ctx *gin.Context) {
		op.Token(ctx, storage)
	})
}
