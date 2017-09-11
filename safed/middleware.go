package main

import (
	"net/http"

	"github.com/bpostlethwaite/safed"
	"github.com/pkg/errors"
)

func (app App) Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if _, err := safed.ValidateToken(r.Context()); err != nil {
			app.LoginView(w, app.LogCtx(r, AppError{err, AuthError}))
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func (app App) AdminAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := safed.ValidateToken(r.Context())
		if err != nil {
			app.LoginView(w, app.LogCtx(r, AppError{err, AuthError}))
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
