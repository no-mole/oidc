package oidc

import "github.com/gin-gonic/gin"

func Init(r *gin.Engine, storage Storage) {
	r.GET("/authorize", func(ctx *gin.Context) {
		Authorize(ctx, storage)
	})
	r.POST("/token", func(ctx *gin.Context) {
		Token(ctx, storage)
	})
	r.GET("/user_info", func(ctx *gin.Context) {
		GetUserInfo(ctx, storage)
	})
	r.GET("/hello", func(ctx *gin.Context) {
		ctx.String(200, "hello word")
	})
	r.GET("/keys", func(ctx *gin.Context) {
		Keys(ctx, storage)
	})
	r.POST("/end_session", func(ctx *gin.Context) {
		EndSession(ctx, storage)
	})
}
