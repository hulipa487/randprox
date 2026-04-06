package db

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")
	// ErrAdminNotFound is returned when an admin is not found
	ErrAdminNotFound = errors.New("admin not found")
	// ErrDuplicateUsername is returned when a username already exists
	ErrDuplicateUsername = errors.New("username already exists")
)

// DB wraps the GORM database connection
type DB struct {
	conn *gorm.DB
}

// New creates a new database connection and auto-migrates the schema
func New(path string) (*DB, error) {
	conn, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Auto-migrate the schema
	if err := conn.AutoMigrate(&User{}, &TrafficStats{}, &Admin{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &DB{conn: conn}, nil
}

// CreateDefaultAdmin creates a default admin user if none exists
func (db *DB) CreateDefaultAdmin(username, password string) error {
	var count int64
	if err := db.conn.Model(&Admin{}).Count(&count).Error; err != nil {
		return err
	}

	if count > 0 {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	admin := &Admin{
		Username:     username,
		PasswordHash: string(hash),
	}

	return db.conn.Create(admin).Error
}

// VerifyAdmin verifies admin credentials
func (db *DB) VerifyAdmin(username, password string) (*Admin, error) {
	var admin Admin
	if err := db.conn.Where("username = ?", username).First(&admin).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAdminNotFound
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)); err != nil {
		return nil, ErrAdminNotFound
	}

	return &admin, nil
}

// ChangeAdminPassword changes the admin password
func (db *DB) ChangeAdminPassword(adminID uint, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return db.conn.Model(&Admin{}).Where("id = ?", adminID).Update("password_hash", string(hash)).Error
}

// CreateUser creates a new user
func (db *DB) CreateUser(username, password, wireguardConfig string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		Username:        username,
		PasswordHash:    string(hash),
		WireGuardConfig: wireguardConfig,
		IsActive:        true,
	}

	if err := db.conn.Create(user).Error; err != nil {
		if db.isDuplicateKeyError(err) {
			return nil, ErrDuplicateUsername
		}
		return nil, err
	}

	return user, nil
}

// GetUser retrieves a user by ID
func (db *DB) GetUser(id uint) (*User, error) {
	var user User
	if err := db.conn.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (db *DB) GetUserByUsername(username string) (*User, error) {
	var user User
	if err := db.conn.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// VerifyUser verifies user credentials
func (db *DB) VerifyUser(username, password string) (*User, error) {
	user, err := db.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// ListUsers lists all users
func (db *DB) ListUsers() ([]User, error) {
	var users []User
	err := db.conn.Order("username ASC").Find(&users).Error
	return users, err
}

// UpdateUser updates a user
func (db *DB) UpdateUser(id uint, username, password, wireguardConfig *string, isActive *bool) (*User, error) {
	user, err := db.GetUser(id)
	if err != nil {
		return nil, err
	}

	updates := make(map[string]interface{})

	if username != nil {
		updates["username"] = *username
	}
	if password != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		updates["password_hash"] = string(hash)
	}
	if wireguardConfig != nil {
		updates["wire_guard_config"] = *wireguardConfig
	}
	if isActive != nil {
		updates["is_active"] = *isActive
	}

	if err := db.conn.Model(user).Updates(updates).Error; err != nil {
		if db.isDuplicateKeyError(err) {
			return nil, ErrDuplicateUsername
		}
		return nil, err
	}

	return db.GetUser(id)
}

// DeleteUser deletes a user
func (db *DB) DeleteUser(id uint) error {
	return db.conn.Delete(&User{}, id).Error
}

// RecordTraffic records traffic statistics for a user
func (db *DB) RecordTraffic(userID uint, bytesUp, bytesDown uint64) error {
	today := time.Now().UTC().Truncate(24 * time.Hour)

	var stats TrafficStats
	err := db.conn.Where("user_id = ? AND date = ?", userID, today).First(&stats).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		stats = TrafficStats{
			UserID:    userID,
			BytesUp:   bytesUp,
			BytesDown: bytesDown,
			Date:      today,
		}
		return db.conn.Create(&stats).Error
	} else if err != nil {
		return err
	}

	return db.conn.Model(&stats).Updates(map[string]interface{}{
		"bytes_up":   gorm.Expr("bytes_up + ?", bytesUp),
		"bytes_down": gorm.Expr("bytes_down + ?", bytesDown),
	}).Error
}

// GetUserStats gets traffic statistics for a user
func (db *DB) GetUserStats(userID uint) (uint64, uint64, error) {
	var result struct {
		TotalUp   uint64
		TotalDown uint64
	}

	err := db.conn.Model(&TrafficStats{}).
		Select("COALESCE(SUM(bytes_up), 0) as total_up, COALESCE(SUM(bytes_down), 0) as total_down").
		Where("user_id = ?", userID).
		Scan(&result).Error

	return result.TotalUp, result.TotalDown, err
}

// GetDailyStats gets daily traffic statistics for a user
func (db *DB) GetDailyStats(userID uint, days int) ([]TrafficStats, error) {
	since := time.Now().UTC().AddDate(0, 0, -days).Truncate(24 * time.Hour)

	var stats []TrafficStats
	err := db.conn.
		Where("user_id = ? AND date >= ?", userID, since).
		Order("date ASC").
		Find(&stats).Error

	return stats, err
}

func (db *DB) isDuplicateKeyError(err error) bool {
	// SQLite duplicate key error message contains "UNIQUE constraint failed"
	return err != nil && len(err.Error()) > 0 && (err.Error()[:15] == "UNIQUE constraint" || err.Error()[:22] == "Error 1062 (23000)")
}
