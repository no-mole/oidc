package oidc

import "github.com/gin-gonic/gin"

func Init(r *gin.Engine, storage Storage) {
	r.GET("/authorize", func(ctx *gin.Context) {
		Authorize(ctx, storage)
	})
	r.GET("/token", func(ctx *gin.Context) {
		Token(ctx, storage)
	})
	r.GET("/user_info", func(ctx *gin.Context) {
		GetUserInfo(ctx, storage)
	})
	r.GET("/hello", func(ctx *gin.Context) {
		ctx.String(200, "hello word")
	})
}
