package admin

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed web/*
var embedFS embed.FS

// ServeFrontend serves the embedded Vue.js frontend
func ServeFrontend() gin.HandlerFunc {
	// Create a sub-filesystem for the web directory
	webFS, err := fs.Sub(embedFS, "web")
	if err != nil {
		// Fallback if web directory doesn't exist
		return func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "randprox admin API",
			})
		}
	}

	fileServer := http.FileServer(http.FS(webFS))

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Check if the file exists in the embedded filesystem
		_, err := webFS.Open(strings.TrimPrefix(path, "/"))
		if err != nil {
			// If file doesn't exist, serve index.html for SPA routing
			c.Request.URL.Path = "/"
		}

		fileServer.ServeHTTP(c.Writer, c.Request)
	}
}
