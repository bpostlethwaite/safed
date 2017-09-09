package main

import (
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	validator "gopkg.in/validator.v2"
)

type User struct {
	ID    string `validate:"len=36"`
	Admin bool   `storm:"index"`
	Name  string `storm:"unique" validate:"min=3,max=40,regexp=^[a-zA-Z]*$"`
	Pass  string `validate:"min=8"`
}

type RawUser struct {
	Name string `validate:"min=3,max=40,regexp=^[a-zA-Z]*$"`
	Pass string `validate:"min=8"`
}

func newUser(username, password string) (*User, error) {
	ru := RawUser{
		Name: username,
		Pass: password,
	}

	if err := validator.Validate(ru); err != nil {
		return nil, errors.WithStack(err)
	}

	ru.Pass = "--------------------------"

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &User{
		ID:   uuid.NewV4().String(),
		Name: username,
		Pass: string(hash),
	}, nil
}
