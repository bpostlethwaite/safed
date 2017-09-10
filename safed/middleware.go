package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/jwtauth"
	"github.com/pkg/errors"
)

func validateToken(ctx context.Context) (jwtauth.Claims, error) {
	token, claims, err := jwtauth.FromContext(ctx)
	if err != nil {
		return claims, AppError{wstack(err), AuthError}
	}

	// jwt-auth automatically handles expirey using the 'exp' claim
	if token == nil || !token.Valid {
		return claims, wstack(fmt.Errorf("Invalid token"))
	}

	return claims, nil
}

func (app App) Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if _, err := validateToken(r.Context()); err != nil {
			app.LoginView(w, app.LogCtx(r, err))
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func (app App) AdminAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := validateToken(r.Context())
		if err != nil {
			app.LoginView(w, app.LogCtx(r, AppError{wstack(err), AuthError}))
			return
		}

		admin, ok := claims.Get("admin")
		if !ok {
			err := errors.New("jwt token admin field corrupt or missing")
			app.LoginView(w, app.LogCtx(r, AppError{err, AuthError}))
			return
		}

		if isAdmin, ok := admin.(bool); !ok {
			err := errors.New("jwt token admin value corrupt or missing")
			app.LoginView(w, app.LogCtx(r, AppError{err, AuthError}))
			return
		} else if !isAdmin {
			err := errors.New("Admin privilege not met")
			app.LoginView(w, app.LogCtx(r, AppError{err, AuthError}))
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}
