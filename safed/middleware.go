package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/jwtauth"
	"github.com/pkg/errors"
)

type HandlerOpts struct {
	View  bool
	Admin bool
}

func (app App) Authenticator(opts HandlerOpts) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				app.HandleError(w, r, AppErr{wstack(err), 401}, opts)
				return
			}

			// jwt-auth automatically handles expirey using the 'exp' claim
			if token == nil || !token.Valid {
				err := wstack(fmt.Errorf("Invalid token"))
				app.HandleError(w, r, AppErr{wstack(err), 401}, opts)
				return
			}

			if opts.Admin {
				admin, ok := claims.Get("admin")
				if !ok {
					app.HandleError(w, r, AppErr{wstack(
						errors.New("jwt token admin field corrupt or missing")),
						401,
					}, opts)
					return
				}

				if isAdmin, ok := admin.(bool); !ok {
					app.HandleError(w, r, AppErr{wstack(
						errors.New("jwt token admin value corrupt or missing")),
						401,
					}, opts)
					return
				} else if !isAdmin {
					app.HandleError(w, r, AppErr{wstack(
						errors.New("Admin privilege not met")),
						401,
					}, opts)
					return
				}
			}

			// Token is authenticated, pass it through
			next.ServeHTTP(w, r)
		})
	}
}

func (app App) UserContext(opts HandlerOpts) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := app.JwtUser(r.Context())
			if err != nil {
				app.HandleError(w, r, AppErr{wstack(err), 500}, opts)
				return
			}

			ctx := context.WithValue(r.Context(), "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
