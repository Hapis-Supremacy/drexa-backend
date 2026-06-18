package auth

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const userClaimsKey contextKey = "user_claims"

// JWTMiddleware validates the access token on every request.
// Token is read from the Authorization header first, then the access_token cookie.
// Injects *JWTClaims into the request context on success.
func JWTMiddleware(tokenSvc TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "unauthorized"})
				return
			}

			claims, err := tokenSvc.ValidateAccessToken(r.Context(), token)
			if err != nil {
				sendJSON(w, http.StatusUnauthorized, MessageResponse{Error: "unauthorized"})
				return
			}

			ctx := context.WithValue(r.Context(), userClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RateLimitMiddleware throttles requests per client IP using a Redis-backed
// fixed window. `name` namespaces the counter so different routes (login,
// register) are limited independently. On limit breach it returns 429.
//
// It fails open: if Redis is unavailable the request is allowed through (and
// logged) so a cache outage cannot lock every user out of authentication.
func RateLimitMiddleware(limiter RateLimiter, name string, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := name + ":" + clientIP(r)

			allowed, err := limiter.Allow(r.Context(), key, limit, window)
			if err != nil {
				log.Printf("ratelimit: %s: %v (allowing request)", name, err)
				next.ServeHTTP(w, r)
				return
			}
			if !allowed {
				sendJSON(w, http.StatusTooManyRequests, MessageResponse{Error: "too many attempts, please try again later"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the originating IP. It honours the left-most X-Forwarded-For
// entry set by a trusted reverse proxy (nginx ingress) and falls back to the
// raw connection address otherwise.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// UserFromContext retrieves the JWT claims injected by JWTMiddleware.
func UserFromContext(ctx context.Context) (*JWTClaims, bool) {
	claims, ok := ctx.Value(userClaimsKey).(*JWTClaims)
	return claims, ok
}

func extractBearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("access_token"); err == nil {
		return c.Value
	}
	return ""
}
