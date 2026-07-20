package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Парсим тело запроса
	var req RegisterRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 2. Валидация входных данных
	if err := validateRegisterRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 3. Проверяем, что email ещё не занят
	exists, err := UserExistsByEmail(req.Email)
	if err != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if exists {
		sendErrorResponse(w, "User with this email already exists", http.StatusConflict)
		return
	}

	// 4. Хешируем пароль (в БД пойдёт только хеш, не открытый пароль)
	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 5. Создаём пользователя
	user, err := CreateUser(req.Email, req.Username, passwordHash)
	if err != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 6. Выдаём JWT токен сразу после регистрации
	token, err := GenerateToken(*user)
	if err != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 7. Отдаём токен и данные пользователя (password_hash скрыт тегом json:"-")
	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, http.StatusCreated)
}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Парсим тело запроса
	var req LoginRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 2. Базовая валидация
	if err := validateLoginRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 3. Ищем пользователя по email
	user, err := GetUserByEmail(req.Email)
	if err != nil {
		// И "нет такого email", и "неверный пароль" -> одинаковый ответ,
		// чтобы не раскрывать, какие email зарегистрированы
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// 4. Сверяем пароль с хешем
	if !CheckPassword(req.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// 5. Выдаём новый токен
	token, err := GenerateToken(*user)
	if err != nil {
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 6. Отдаём токен и данные пользователя
	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, http.StatusOK)
}

// ProfileHandler возвращает профиль текущего пользователя
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Достаём userID из контекста (его положил туда AuthMiddleware)
	userID, ok := GetUserIDFromContext(r)
	if !ok {
		sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Загружаем пользователя из БД
	user, err := GetUserByID(userID)
	if err != nil {
		sendErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	// 3. Возвращаем профиль (password_hash скрыт тегом json:"-")
	sendJSONResponse(w, user, http.StatusOK)
}

// HealthHandler проверяет состояние сервиса
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем подключение к БД
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	// Возвращаем статус OK
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	json.NewEncoder(w).Encode(response)
}

// sendJSONResponse отправляет JSON ответ (вспомогательная функция)
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse отправляет JSON ответ с ошибкой (вспомогательная функция)
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// parseJSONRequest парсит JSON из тела запроса (вспомогательная функция)
func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Строгая проверка полей

	return decoder.Decode(v)
}

// validateRegisterRequest валидирует данные регистрации
func validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	if err := ValidateEmail(req.Email); err != nil {
		return err
	}
	if len(req.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	if err := ValidatePassword(req.Password); err != nil {
		return err
	}

	return nil
}

// validateLoginRequest валидирует данные входа
func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
