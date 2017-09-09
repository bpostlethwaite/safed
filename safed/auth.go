package main

import (
	"fmt"
	"time"

	"github.com/go-chi/jwtauth"
	"golang.org/x/crypto/bcrypt"
)

func DefaultExpiry() time.Time {
	return time.Now().Add(24 * 30 * time.Hour)
}

func (app App) AuthToken(username, password string, expiry time.Time) (string, error) {
	var user User
	app.LogDebug(
		fmt.Sprintf("AuthToken: accessing db with username: '%s'", username))

	err := app.Db.One("Name", username, &user)
	if err != nil {
		return "", wstack(wmsg(err,
			"AuthToken: couldn't find: '"+username+"' in db"))
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Pass), []byte(password))
	if err != nil {
		return "", wstack(wmsg(err, "AuthToken: Password mismatch"))
	}

	claims := jwtauth.Claims{
		"iss":   app.Domain,
		"subi":  user.ID,
		"subn":  user.Name,
		"admin": user.Admin,
	}

	_, tokenString, err := app.Auth.Encode(
		claims.SetIssuedNow().SetExpiry(expiry),
	)

	return tokenString, wstack(err)
}
