package auth

import (
	"encoding/json"
	"net/http"
)

// DTO

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type VerifyRequest struct {
	UserID string `json:"user_id"`
	OTP    string `json:"otp"`
}

type OAuthRequest struct {
	Provider    string `json:"provider"`
	ProviderUID string `json:"provider_uid"`
	Email       string `json:"email,omitempty"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type ChangePasswordRequest struct {
	UserID      string `json:"user_id"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type TradingPinRequest struct {
	UserID string `json:"user_id"`
	Pin    string `json:"pin"`
}

type MessageResponse struct {
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// HELPER

func sendJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func setAuthCookies(w http.ResponseWriter, access, refresh string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   900,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   604800,
	})
}

// HANDLERS

// 1. REGISTER
func HandleRegister(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, 400, MessageResponse{Error: "invalid input"})
			return
		}

		_, err := u.Register(r.Context(), req.Email, req.Password)
		if err != nil {
			sendJSON(w, 409, MessageResponse{Error: err.Error()})
			return
		}

		sendJSON(w, 200, MessageResponse{Message: "OTP sent"})
	}
}

// 2. LOGIN
func HandleLogin(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		json.NewDecoder(r.Body).Decode(&req)

		token, err := u.Login(r.Context(), req.Email, req.Password)
		if err != nil {
			sendJSON(w, 401, MessageResponse{Error: "invalid credentials"})
			return
		}

		setAuthCookies(w, token.AccessToken, token.RefreshToken)
		sendJSON(w, 200, MessageResponse{Message: "login success"})
	}
}

// 3. LOGOUT
func HandleLogout(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("refresh_token")
		if err == nil {
			_ = u.Logout(r.Context(), c.Value)
		}
		sendJSON(w, 200, MessageResponse{Message: "logout success"})
	}
}

// 4. REFRESH
func HandleRefreshToken(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("refresh_token")
		if err != nil {
			sendJSON(w, 401, MessageResponse{Error: "expired"})
			return
		}

		token, err := u.RefreshToken(r.Context(), c.Value)
		if err != nil {
			sendJSON(w, 401, MessageResponse{Error: "invalid token"})
			return
		}

		setAuthCookies(w, token.AccessToken, token.RefreshToken)
		sendJSON(w, 200, MessageResponse{Message: "refreshed"})
	}
}

// 5. VERIFY EMAIL
func HandleVerifyEmail(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyRequest
		json.NewDecoder(r.Body).Decode(&req)

		ok, err := u.VerifyEmail(r.Context(), req.UserID, req.OTP)
		if err != nil || !ok {
			sendJSON(w, 401, MessageResponse{Error: "invalid otp"})
			return
		}

		sendJSON(w, 200, MessageResponse{Message: "email verified"})
	}
}

// 6. VERIFY PHONE
func HandleVerifyPhone(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyRequest
		json.NewDecoder(r.Body).Decode(&req)

		ok, err := u.VerifyPhone(r.Context(), req.UserID, req.OTP)
		if err != nil || !ok {
			sendJSON(w, 401, MessageResponse{Error: "invalid otp"})
			return
		}

		sendJSON(w, 200, MessageResponse{Message: "phone verified"})
	}
}

// 7. REQUEST RESET
func HandleRequestPasswordReset(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Email string }
		json.NewDecoder(r.Body).Decode(&req)

		_ = u.RequestPasswordReset(r.Context(), req.Email)
		sendJSON(w, 200, MessageResponse{Message: "email sent"})
	}
}

// 8. RESET PASSWORD
func HandleResetPassword(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ResetPasswordRequest
		json.NewDecoder(r.Body).Decode(&req)

		err := u.ResetPassword(r.Context(), req.Token, req.NewPassword)
		if err != nil {
			sendJSON(w, 400, MessageResponse{Error: err.Error()})
			return
		}

		sendJSON(w, 200, MessageResponse{Message: "password updated"})
	}
}

// 9. OAUTH REGISTER
func HandleRegisterWithOAuth(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req OAuthRequest
		json.NewDecoder(r.Body).Decode(&req)

		_, err := u.RegisterWithOAuth(r.Context(), req.Provider, req.ProviderUID, req.Email)
		if err != nil {
			sendJSON(w, 409, MessageResponse{Error: err.Error()})
			return
		}

		sendJSON(w, 201, MessageResponse{Message: "oauth register success"})
	}
}

// 10. OAUTH LOGIN
func HandleLoginWithOAuth(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req OAuthRequest
		json.NewDecoder(r.Body).Decode(&req)

		token, err := u.LoginWithOAuth(r.Context(), req.Provider, req.ProviderUID)
		if err != nil {
			sendJSON(w, 401, MessageResponse{Error: "oauth failed"})
			return
		}

		setAuthCookies(w, token.AccessToken, token.RefreshToken)
		sendJSON(w, 200, MessageResponse{Message: "oauth login success"})
	}
}

// 11. CHANGE PASSWORD
func HandleChangePassword(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ChangePasswordRequest
		json.NewDecoder(r.Body).Decode(&req)

		err := u.ChangePassword(r.Context(), req.UserID, req.OldPassword, req.NewPassword)
		if err != nil {
			sendJSON(w, 400, MessageResponse{Error: err.Error()})
			return
		}

		sendJSON(w, 200, MessageResponse{Message: "password changed"})
	}
}

// 12. LOGOUT ALL
func HandleLogoutAll(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")

		err := u.LogoutAll(r.Context(), userID)
		if err != nil {
			sendJSON(w, 500, MessageResponse{Error: err.Error()})
			return
		}

		sendJSON(w, 200, MessageResponse{Message: "all sessions revoked"})
	}
}

// 13. SET PIN
func HandleSetTradingPin(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TradingPinRequest
		json.NewDecoder(r.Body).Decode(&req)

		err := u.SetTradingPin(r.Context(), req.UserID, req.Pin)
		if err != nil {
			sendJSON(w, 400, MessageResponse{Error: err.Error()})
			return
		}

		sendJSON(w, 200, MessageResponse{Message: "pin set"})
	}
}

// 14. VERIFY PIN
func HandleVerifyTradingPin(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TradingPinRequest
		json.NewDecoder(r.Body).Decode(&req)

		ok, err := u.VerifyTradingPin(r.Context(), req.UserID, req.Pin)
		if err != nil || !ok {
			sendJSON(w, 401, MessageResponse{Error: "invalid pin"})
			return
		}

		sendJSON(w, 200, MessageResponse{Message: "pin verified"})
	}
}
