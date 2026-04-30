package handlers

import (
	"fmt"
	"iam-service/internal/service"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type AuthHandler struct {
	tokenService *service.TokenService
	redisClient  *redis.Client
}

func (h *AuthHandler) VerifyToken(c *gin.Context) {
	// Извлечение токена из заголовка Authorization
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.AbortWithStatusJSON(401, gin.H{"error": "missing authorization header"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		c.AbortWithStatusJSON(401, gin.H{"error": "invalid token format"})
		return
	}

	// Парсинг и валидация токена
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверка алгоритма подписи (защита от alg:none атак)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.tokenService.GetAccessSecret(), nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
		return
	}

	// Извлечение claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(401, gin.H{"error": "invalid claims"})
		return
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		c.AbortWithStatusJSON(401, gin.H{"error": "missing user id"})
		return
	}

	// Передача user_id в бэкенд через заголовок
	c.Header("X-User-ID", userID)
	c.Status(200)
}
