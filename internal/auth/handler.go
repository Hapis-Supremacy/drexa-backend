package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

// ─── DTOs ────────────────────────────────────────────────────────────────────

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type VerifyRequest struct {
	UserID string `json:"user_id"`
	OTP    string `json:"otp"`
}

type SetPinRequest struct {
	Pin string `json:"pin"`
}

type MessageResponse struct {
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func sendJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func setAuthCookies(w http.ResponseWriter, access, refresh string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   900,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   604800,
	})
}

// ─── Public Auth Handlers ─────────────────────────────────────────────────────

// HandleRegister creates a new account with email + password and issues JWT cookies.
func HandleRegister(u AuthUsecase, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, http.StatusBadRequest, MessageResponse{Error: "invalid input"})
			return
		}

		token, err := u.Register(r.Context(), req.Email, req.Password, req.Username)
		if err != nil {
			switch {
			case errors.Is(err, ErrEmailAlreadyExists):
				sendJSON(w, http.StatusConflict, MessageResponse{Error: "email already registered"})
			default:
				sendJSON(w, http.StatusBadRequest, MessageResponse{Error: err.Error()})
			}
			return
		}

		setAuthCookies(w, token.AccessToken, token.RefreshToken, secureCookies)
		sendJSON(w, http.StatusCreated, MessageResponse{Message: "registration successful"})
	}
}

// HandleLogin verifies email + password and issues JWT cookies.
func HandleLogin(u AuthUsecase, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, http.StatusBadRequest, MessageResponse{Error: "invalid input"})
			return
		}

		token, err := u.Login(r.Context(), req.Email, req.Password)
		if err != nil {
			if errors.Is(err, ErrInvalidCredentials) {
				sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "invalid email or password"})
				return
			}
			sendJSON(w, http.StatusInternalServerError, MessageResponse{Error: "login failed"})
			return
		}

		setAuthCookies(w, token.AccessToken, token.RefreshToken, secureCookies)
		sendJSON(w, http.StatusOK, MessageResponse{Message: "login successful"})
	}
}

func HandleLogout(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("refresh_token"); err == nil {
			if logErr := u.Logout(r.Context(), c.Value); logErr != nil {
				log.Printf("logout: failed to revoke refresh token: %v", logErr)
			}
		}
		sendJSON(w, http.StatusOK, MessageResponse{Message: "logged out"})
	}
}

func HandleRefreshToken(u AuthUsecase, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("refresh_token")
		if err != nil {
			sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "missing refresh token"})
			return
		}

		token, err := u.RefreshToken(r.Context(), c.Value)
		if err != nil {
			sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "invalid or expired token"})
			return
		}

		setAuthCookies(w, token.AccessToken, token.RefreshToken, secureCookies)
		sendJSON(w, http.StatusOK, MessageResponse{Message: "token refreshed"})
	}
}

func HandleVerifyPhone(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, http.StatusBadRequest, MessageResponse{Error: "invalid input"})
			return
		}

		ok, err := u.VerifyPhone(r.Context(), req.UserID, req.OTP)
		if err != nil || !ok {
			sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "invalid or expired OTP"})
			return
		}

		sendJSON(w, http.StatusOK, MessageResponse{Message: "phone verified"})
	}
}

// ─── Protected Auth Handlers (require JWTMiddleware) ─────────────────────────

func HandleLogoutAll(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := UserFromContext(r.Context())
		if !ok {
			sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "unauthorized"})
			return
		}

		if err := u.LogoutAll(r.Context(), claims.UserID); err != nil {
			sendJSON(w, http.StatusInternalServerError, MessageResponse{Error: err.Error()})
			return
		}

		sendJSON(w, http.StatusOK, MessageResponse{Message: "all sessions revoked"})
	}
}

func HandleSetTradingPin(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := UserFromContext(r.Context())
		if !ok {
			sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "unauthorized"})
			return
		}

		var req SetPinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, http.StatusBadRequest, MessageResponse{Error: "invalid input"})
			return
		}

		if err := u.SetTradingPin(r.Context(), claims.UserID, req.Pin); err != nil {
			sendJSON(w, http.StatusBadRequest, MessageResponse{Error: err.Error()})
			return
		}

		sendJSON(w, http.StatusOK, MessageResponse{Message: "trading pin set"})
	}
}

func HandleVerifyTradingPin(u AuthUsecase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := UserFromContext(r.Context())
		if !ok {
			sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "unauthorized"})
			return
		}

		var req SetPinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSON(w, http.StatusBadRequest, MessageResponse{Error: "invalid input"})
			return
		}

		ok2, err := u.VerifyTradingPin(r.Context(), claims.UserID, req.Pin)
		if err != nil || !ok2 {
			sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "invalid pin"})
			return
		}

		sendJSON(w, http.StatusOK, MessageResponse{Message: "pin verified"})
	}
}
