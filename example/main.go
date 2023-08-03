package main

import (
	"github.com/gin-gonic/gin"
	"github.com/no-mole/oidc/example/example"
	"github.com/no-mole/oidc/pkg/oidc"
)

func main() {
	storage := example.NewStorage(example.NewUserStorage())

	r := gin.New()
	oidc.Init(r, storage)
	r.Run(":9998")
}
