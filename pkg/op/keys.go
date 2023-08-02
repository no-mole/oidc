package op

import (
	"github.com/gin-gonic/gin"
	"github.com/square/go-jose/v3"
	"net/http"
)

func Keys(ctx *gin.Context, storage Storage) {
	keySet, err := storage.KeySet()
	if err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorServer)
		return
	}
	ctx.JSON(http.StatusOK, jsonWebKeySet(keySet))
}

func jsonWebKeySet(keys []Key) *jose.JSONWebKeySet {
	webKeys := make([]jose.JSONWebKey, len(keys))
	for i, key := range keys {
		webKeys[i] = jose.JSONWebKey{
			KeyID:     key.ID(),
			Algorithm: string(key.Algorithm()),
			Use:       key.Use(),
			Key:       key.Key(),
		}
	}
	return &jose.JSONWebKeySet{Keys: webKeys}
}
