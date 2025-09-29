package types

// LoginResponse represents the response for login requests
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Role         string `json:"role"`
	Username     string `json:"username"`
}

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// SuccessResponse represents a standard success response
type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// StatusResponse represents VPN instance status response
type StatusResponse struct {
	State  string `json:"state"`
	Name   string `json:"name"`
	Region string `json:"region,omitempty"`
}
