package protocol

// Protocol constants for client-server communication
const (
	// Commands
	CmdRegister      = "REGISTER"
	CmdLogin         = "LOGIN"
	CmdRequestToken  = "REQUEST_TOKEN"
	
	// Responses
	RespRegistered      = "REGISTERED"
	RespAuthenticated   = "AUTHENTICATED"
	RespToken           = "TOKEN"
	RespValidationCode  = "VALIDATION_CODE"
	RespError           = "ERROR"
	
	// Error types
	ErrInvalidRequest      = "INVALID_REQUEST"
	ErrInvalidRegister     = "INVALID_REGISTER"
	ErrInvalidLogin        = "INVALID_LOGIN"
	ErrInvalidToken        = "INVALID_TOKEN"
	ErrInvalidCredentials  = "INVALID_CREDENTIALS"
	ErrServerError         = "SERVER_ERROR"
	ErrUnknownCommand      = "UNKNOWN_COMMAND"
)

// FormatRegisterRequest formats a registration request
func FormatRegisterRequest(token, validationCode, password string) string {
	return CmdRegister + ":" + token + ":" + validationCode + ":" + password
}

// FormatLoginRequest formats a login request
func FormatLoginRequest(username, password string) string {
	return CmdLogin + ":" + username + ":" + password
}

// FormatRequestTokenRequest formats a token request
func FormatRequestTokenRequest() string {
	return CmdRequestToken
}

// FormatRegisteredResponse formats a successful registration response
func FormatRegisteredResponse(username string) string {
	return RespRegistered + ":" + username
}

// FormatTokenResponse formats a token response (deprecated - now split for security)
func FormatTokenResponse(token, validationCode string) string {
	return RespToken + ":" + token + ":" + validationCode
}

// FormatValidationCodeResponse formats a validation code response
func FormatValidationCodeResponse(validationCode string) string {
	return RespValidationCode + ":" + validationCode
}

// FormatErrorResponse formats an error response
func FormatErrorResponse(errorType string) string {
	return RespError + ":" + errorType
}