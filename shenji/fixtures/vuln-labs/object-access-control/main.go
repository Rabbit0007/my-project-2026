package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	store := NewStore()

	router.GET("/documents/:id", func(c *gin.Context) {
		currentUserID := c.GetHeader("X-User-ID")
		_ = currentUserID
		id := c.Param("id")
		document, ok := store.GetDocument(id)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "missing"})
			return
		}
		c.JSON(http.StatusOK, document)
	})

	_ = router.Run(":8080")
}
