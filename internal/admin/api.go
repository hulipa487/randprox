package admin

import (
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"randprox/internal/db"
	"randprox/internal/wireguard"
)

// APIHandler contains dependencies for the admin API
type APIHandler struct {
	db        *db.DB
	deviceMgr *wireguard.DeviceManager
}

// NewAPIHandler creates a new APIHandler
func NewAPIHandler(database *db.DB, deviceMgr *wireguard.DeviceManager) *APIHandler {
	return &APIHandler{
		db:        database,
		deviceMgr: deviceMgr,
	}
}

// SetupRoutes sets up the Gin routes
func (h *APIHandler) SetupRoutes(r *gin.Engine) {
	// API routes
	api := r.Group("/api")
	{
		// Admin login (no auth required)
		api.POST("/admin/login", h.Login)

		// Protected routes
		protected := api.Group("")
		protected.Use(AuthMiddleware())
		{
			// Admin routes
			admin := protected.Group("/admin")
			{
				admin.POST("/change-password", h.ChangePassword)
			}

			// User routes
			users := protected.Group("/users")
			{
				users.GET("", h.ListUsers)
				users.POST("", h.CreateUser)
				users.GET("/:id", h.GetUser)
				users.PUT("/:id", h.UpdateUser)
				users.DELETE("/:id", h.DeleteUser)
				users.POST("/:id/reload", h.ReloadUser)
				users.GET("/:id/stats", h.GetUserStats)
			}
		}
	}

	// Serve frontend (catch-all)
	r.NoRoute(ServeFrontend())
}

// Login handles admin login
func (h *APIHandler) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	admin, err := h.db.VerifyAdmin(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := GenerateToken(admin.ID, admin.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"username": admin.Username,
	})
}

// ChangePassword handles admin password change
func (h *APIHandler) ChangePassword(c *gin.Context) {
	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	adminID, err := GetAdminID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if err := h.db.ChangeAdminPassword(adminID, req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to change password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// ListUsers lists all users
func (h *APIHandler) ListUsers(c *gin.Context) {
	users, err := h.db.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	// Include stats for each user
	type userWithStats struct {
		db.User
		BytesUp   uint64 `json:"bytes_up"`
		BytesDown uint64 `json:"bytes_down"`
	}

	result := make([]userWithStats, 0, len(users))
	for _, user := range users {
		up, down, _ := h.db.GetUserStats(user.ID)
		result = append(result, userWithStats{
			User:      user,
			BytesUp:   up,
			BytesDown: down,
		})
	}

	c.JSON(http.StatusOK, result)
}

// CreateUser creates a new user
func (h *APIHandler) CreateUser(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	// Get WireGuard config from file upload or text
	var wireguardConfig string

	// Check for file upload
	file, _, err := c.Request.FormFile("wireguard_config_file")
	if err == nil {
		defer file.Close()
		content, err := io.ReadAll(file)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read uploaded file"})
			return
		}
		wireguardConfig = string(content)
	} else {
		// Fall back to text field
		wireguardConfig = c.PostForm("wireguard_config")
	}

	if wireguardConfig == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "WireGuard config is required"})
		return
	}

	// Validate WireGuard config
	if _, err := wireguard.ParseConfig(wireguardConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid WireGuard config: " + err.Error()})
		return
	}

	user, err := h.db.CreateUser(username, password, wireguardConfig)
	if err != nil {
		if err == db.ErrDuplicateUsername {
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// GetUser gets a user by ID
func (h *APIHandler) GetUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := h.db.GetUser(uint(id))
	if err != nil {
		if err == db.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// UpdateUser updates a user
func (h *APIHandler) UpdateUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Get form data
	username := c.PostForm("username")
	password := c.PostForm("password")
	isActiveStr := c.PostForm("is_active")

	var usernamePtr *string
	if username != "" {
		usernamePtr = &username
	}

	var passwordPtr *string
	if password != "" {
		passwordPtr = &password
	}

	var isActivePtr *bool
	if isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			isActivePtr = &isActive
		}
	}

	// Get WireGuard config
	var wireguardConfigPtr *string
	file, _, err := c.Request.FormFile("wireguard_config_file")
	if err == nil {
		defer file.Close()
		content, err := io.ReadAll(file)
		if err == nil {
			wgConfig := string(content)
			wireguardConfigPtr = &wgConfig
		}
	} else {
		wgConfig := c.PostForm("wireguard_config")
		if wgConfig != "" {
			wireguardConfigPtr = &wgConfig
		}
	}

	// Validate WireGuard config if provided
	if wireguardConfigPtr != nil {
		if _, err := wireguard.ParseConfig(*wireguardConfigPtr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid WireGuard config: " + err.Error()})
			return
		}
	}

	user, err := h.db.UpdateUser(uint(id), usernamePtr, passwordPtr, wireguardConfigPtr, isActivePtr)
	if err != nil {
		if err == db.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if err == db.ErrDuplicateUsername {
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// Reload user's device if config changed
	h.deviceMgr.ReloadUser(user.Username)

	c.JSON(http.StatusOK, user)
}

// DeleteUser deletes a user
func (h *APIHandler) DeleteUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Get user first to get username
	user, err := h.db.GetUser(uint(id))
	if err == nil {
		h.deviceMgr.RemoveUser(user.Username)
	}

	if err := h.db.DeleteUser(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// ReloadUser reloads a user's WireGuard device
func (h *APIHandler) ReloadUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := h.db.GetUser(uint(id))
	if err != nil {
		if err == db.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	h.deviceMgr.ReloadUser(user.Username)
	c.JSON(http.StatusOK, gin.H{"message": "User device reloaded successfully"})
}

// GetUserStats gets traffic stats for a user
func (h *APIHandler) GetUserStats(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	up, down, err := h.db.GetUserStats(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user stats"})
		return
	}

	// Get daily stats for the last 30 days
	daily, err := h.db.GetDailyStats(uint(id), 30)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get daily stats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total_bytes_up":   up,
		"total_bytes_down": down,
		"daily":            daily,
	})
}
