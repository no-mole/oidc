package main

import (
	"github.com/gin-gonic/gin"
	"oidc/example/example"
	"oidc/pkg/oidc"
)

func main() {
	storage := example.NewStorage(example.NewUserStorage())

	r := gin.New()
	oidc.Init(r, storage)
	r.Run(":9998")
}
