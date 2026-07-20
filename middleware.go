package main

import (
	"context"
	"net/http"
	"strings"
)

// contextKey — свой тип для ключа контекста, чтобы не было коллизий со строками
type contextKey string

const userIDKey contextKey = "userID"

// AuthMiddleware проверяет JWT токен и устанавливает контекст пользователя
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendErrorResponse(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Ожидаем строго формат "Bearer <token>"
		if !strings.HasPrefix(authHeader, "Bearer ") {
			sendErrorResponse(w, "Invalid authorization format, expected 'Bearer <token>'", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := ValidateToken(tokenString)
		if err != nil {
			sendErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Кладём ID пользователя в контекст, чтобы обработчик мог его достать
		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetUserIDFromContext извлекает ID пользователя из контекста
func GetUserIDFromContext(r *http.Request) (int, bool) {
	userID, ok := r.Context().Value(userIDKey).(int)
	return userID, ok
}
