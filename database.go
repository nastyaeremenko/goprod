package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Глобальная переменная для подключения к БД
var db *sql.DB

// InitDB инициализирует подключение к базе данных
func InitDB() error {
	// TODO: Реализуйте подключение к PostgreSQL
	//
	// Что нужно сделать:
	// 1. Составьте строку подключения используя fmt.Sprintf()
	//    Формат: "host=%s port=%s user=%s password=%s dbname=%s sslmode=disable"
	// 2. Получите параметры из переменных окружения с помощью getEnv()
	// 3. Откройте соединение с sql.Open("postgres", connStr)
	// 4. Проверьте подключение с помощью db.Ping()
	// 5. Обработайте ошибки на каждом шаге
	//
	// Переменные окружения: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", "postgres"),
		getEnv("DB_NAME", "secure_service"),
	)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	return nil
}

// CloseDB закрывает соединение с базой данных
func CloseDB() {
	if db != nil {
		db.Close()
	}
}

// CreateUser создает нового пользователя в базе данных
func CreateUser(email, username, passwordHash string) (*User, error) {
	// Плейсхолдеры $1, $2, $3 — драйвер сам экранирует значения => защита от SQL-инъекций
	query := `INSERT INTO users (email, username, password_hash)
	          VALUES ($1, $2, $3)
	          RETURNING id, created_at`

	user := &User{
		Email:        email,
		Username:     username,
		PasswordHash: passwordHash,
	}

	err := db.QueryRow(query, email, username, passwordHash).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return user, nil
}

// GetUserByEmail находит пользователя по email
func GetUserByEmail(email string) (*User, error) {
	// password_hash здесь нужен, чтобы потом сверить пароль при логине
	query := `SELECT id, email, username, password_hash, created_at
	          FROM users WHERE email = $1`

	user := &User{}
	err := db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows // пользователь не найден
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %v", err)
	}

	return user, nil
}

// GetUserByID находит пользователя по ID
func GetUserByID(userID int) (*User, error) {
	// password_hash не выбираем — для профиля он не нужен
	query := `SELECT id, email, username, created_at
	          FROM users WHERE id = $1`

	user := &User{}
	err := db.QueryRow(query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows // пользователь не найден
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by id: %v", err)
	}

	return user, nil
}

// UserExistsByEmail проверяет, существует ли пользователь с данным email
func UserExistsByEmail(email string) (bool, error) {
	// EXISTS вернёт true/false, не вытягивая всю строку — это дешевле
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	var exists bool
	err := db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %v", err)
	}

	return exists, nil
}

// GetDB возвращает подключение к базе данных (для тестирования)
func GetDB() *sql.DB {
	return db
}
