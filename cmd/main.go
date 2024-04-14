package main

import (
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"main.go/internal/service"
)

func main() {
	router := gin.Default()

	authMiddleware := func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		token, err := jwt.Parse(tokenString, service.SecretKeyFunc)
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}

	router.POST("/auth", func(c *gin.Context) {
		var authReq service.AuthRequest
		if err := c.ShouldBindJSON(&authReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		userID, isAdmin, err := service.AuthenticateUser(authReq.Username, authReq.Password)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
			return
		}

		tokenString, err := service.GenerateJWT(userID, isAdmin) // Передача флага isAdmin
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})
	router.GET("/user_banner", service.GetUserBanner)
	router.GET("/banner", authMiddleware, service.GetBanners)          // Только для админов с проверкой токена
	router.POST("/banner", authMiddleware, service.CreateBanner)       // Только для админов с проверкой токена
	router.PATCH("/banner/:id", authMiddleware, service.UpdateBanner)  // Только для админов с проверкой токена
	router.DELETE("/banner/:id", authMiddleware, service.DeleteBanner) // Только для админов с проверкой токена

	// Запускаем HTTP сервер на порту 8080
	router.Run(":8080")
}
