package admin

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// ServeFrontend serves a placeholder (frontend to be implemented)
func ServeFrontend() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "randprox admin API",
		})
	}
}
