package oidc

import "github.com/gin-gonic/gin"

func Init(r *gin.Engine, storage Storage) {
	r.GET("/authorize", func(ctx *gin.Context) {
		Authorize(ctx, storage)
	})
}
