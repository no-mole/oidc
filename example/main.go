package main

import (
	"github.com/gin-gonic/gin"
	"oidc/example/example"
	"oidc/pkg/op"
)

func main() {
	storage := example.NewStorage(example.NewUserStorage())

	r := gin.New()
	op.Init(r, storage)
	r.Run(":9998")
}
