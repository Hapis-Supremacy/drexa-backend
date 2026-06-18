package usecase

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"drexa/internal/auth"
)

var pinRegexp = regexp.MustCompile(`^\d{6}$`)

type authUsecase struct {
	userRepo         auth.UserRepository
	refreshTokenRepo auth.RefreshTokenRepository
	otpService       auth.OTPService
	tokenService     auth.TokenService
}

func NewAuthUsecase(
	userRepo auth.UserRepository,
	refreshTokenRepo auth.RefreshTokenRepository,
	otpService auth.OTPService,
	tokenService auth.TokenService,
) auth.AuthUsecase {
	return &authUsecase{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		otpService:       otpService,
		tokenService:     tokenService,
	}
}

var emailRegexp = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Register creates a new user with an email + password and issues a token pair.
func (uc *authUsecase) Register(ctx context.Context, email, password, username string) (*auth.AuthToken, error) {
	if !emailRegexp.MatchString(email) {
		return nil, errors.New("invalid email address")
	}
	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}

	// Reject duplicate emails before attempting to create.
	if _, err := uc.userRepo.FindByEmail(ctx, email); err == nil {
		return nil, auth.ErrEmailAlreadyExists
	} else if !errors.Is(err, auth.ErrUserNotFound) {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}

	user := &auth.User{
		UserID:       uuid.NewString(),
		Email:        email,
		UserName:     username,
		PasswordHash: string(hash),
		LastLoginAt:  time.Now(),
	}
	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, errors.New("failed to create user")
	}

	return uc.issueTokenPair(ctx, user)
}

// Login verifies the email + password and issues a token pair.
// It returns ErrInvalidCredentials for both unknown email and wrong password
// so the response does not reveal which one was incorrect.
func (uc *authUsecase) Login(ctx context.Context, email, password string) (*auth.AuthToken, error) {
	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, auth.ErrInvalidCredentials
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, auth.ErrInvalidCredentials
	}

	return uc.issueTokenPair(ctx, user)
}

func (uc *authUsecase) SendPhoneVerificationOTP(ctx context.Context, userID string) error {
	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		return auth.ErrUserNotFound
	}
	return uc.otpService.GenerateAndSendSMS(ctx, fmt.Sprintf("otp:phone:%s", user.PhoneNumber), user.PhoneNumber)
}

func (uc *authUsecase) VerifyPhone(ctx context.Context, userID, otp string) (bool, error) {
	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		return false, auth.ErrUserNotFound
	}

	ok, err := uc.otpService.Verify(ctx, fmt.Sprintf("otp:phone:%s", user.PhoneNumber), otp)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	return true, uc.userRepo.UpdatePhoneVerified(ctx, userID, true)
}

func (uc *authUsecase) RefreshToken(ctx context.Context, rawToken string) (*auth.AuthToken, error) {
	hash := uc.tokenService.HashToken(rawToken)
	stored, err := uc.refreshTokenRepo.FindByTokenHash(ctx, hash)
	if err != nil {
		return nil, auth.ErrTokenInvalid
	}

	if stored.RevokedAt != nil || time.Now().After(stored.ExpiresAt) {
		return nil, auth.ErrTokenExpired
	}

	user, err := uc.userRepo.FindByID(ctx, stored.UserID)
	if err != nil {
		return nil, auth.ErrUserNotFound
	}

	_ = uc.refreshTokenRepo.Revoke(ctx, stored.TokenID)
	return uc.issueTokenPair(ctx, user)
}

func (uc *authUsecase) Logout(ctx context.Context, rawToken string) error {
	hash := uc.tokenService.HashToken(rawToken)
	stored, err := uc.refreshTokenRepo.FindByTokenHash(ctx, hash)
	if err != nil {
		return nil
	}
	return uc.refreshTokenRepo.Revoke(ctx, stored.TokenID)
}

func (uc *authUsecase) LogoutAll(ctx context.Context, userID string) error {
	return uc.refreshTokenRepo.RevokeAllByUserID(ctx, userID)
}

func (uc *authUsecase) SetTradingPin(ctx context.Context, userID, pin string) error {
	if !pinRegexp.MatchString(pin) {
		return errors.New("pin must be exactly 6 digits")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to hash pin")
	}
	return uc.userRepo.UpdateTradingPinHash(ctx, userID, string(hash))
}

func (uc *authUsecase) VerifyTradingPin(ctx context.Context, userID, pin string) (bool, error) {
	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		return false, auth.ErrUserNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.TradingPinHash), []byte(pin)); err != nil {
		return false, nil
	}
	return true, nil
}

func (uc *authUsecase) issueTokenPair(ctx context.Context, user *auth.User) (*auth.AuthToken, error) {
	accToken, err := uc.tokenService.GenerateAccessToken(ctx, user)
	if err != nil {
		return nil, err
	}

	rawRefToken, err := uc.tokenService.GenerateRefreshToken(ctx, user.UserID)
	if err != nil {
		return nil, err
	}

	record := &auth.RefreshToken{
		TokenID:   uuid.NewString(),
		UserID:    user.UserID,
		TokenHash: uc.tokenService.HashToken(rawRefToken),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	if err := uc.refreshTokenRepo.Create(ctx, record); err != nil {
		return nil, err
	}

	if err := uc.userRepo.UpdateLastLoginAt(ctx, user.UserID); err != nil {
		log.Printf("issueTokenPair: failed to update last_login_at for user %s: %v", user.UserID, err)
	}

	return &auth.AuthToken{
		AccessToken:  accToken,
		RefreshToken: rawRefToken,
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(15 * time.Minute),
	}, nil
}
