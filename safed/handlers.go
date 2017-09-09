package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/bpostlethwaite/safed"
)

type PageContext struct {
	NewUserError    string
	UpdateUserError string
	Title           template.HTML
	Username        template.HTML
	Users           []User
}

func (app App) HandleError(w http.ResponseWriter, r *http.Request, err AppErr, opts HandlerOpts) {
	app.LogError(err)
	if opts.View {
		if err.Code == 401 {
			// should allow login to redirect to original request URL with
			// something like ?next=
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			http.Error(w, http.StatusText(err.Code), err.Code)
		}
	} else {
		http.Error(w, http.StatusText(err.Code), err.Code)
	}
}

func (app App) Login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.HandleError(w, r, AppErr{wstack(err), 500}, HandlerOpts{})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	expiry := DefaultExpiry()
	app.LogDebug("Running AuthToken for username:password '" +
		username + ":xxxxxxxx'")
	tokenString, err := app.AuthToken(username, password, expiry)
	if err != nil {
		app.HandleError(w, r, AppErr{wstack(err), 401}, HandlerOpts{})
		return
	}

	app.LogDebug(fmt.Sprintf(
		"signed new authtoken %s for user %s", tokenString, username))

	cookie := http.Cookie{
		Name:     "jwt",
		Value:    tokenString,
		Domain:   app.Domain,
		Expires:  expiry,
		HttpOnly: true,
		Secure:   app.Https,
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app App) Logout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "jwt",
		Value:    "deleted",
		Domain:   app.Domain,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   app.Https,
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (app App) LoginView(w http.ResponseWriter, r *http.Request) {
	user, err := app.JwtUser(r.Context())
	if err == nil {
		app.Render(w, r, "logout", PageContext{
			Username: template.HTML(user.Name),
			Title:    template.HTML(app.Name),
		})
	} else {
		app.Render(w, r, "login", PageContext{
			Username: template.HTML("anonymous"),
			Title:    template.HTML(app.Name),
		})
	}
}

func (app App) PageContext(ctx context.Context) PageContext {
	return PageContext{
		Title: template.HTML(app.Name),
	}
}

func (app App) SplashView(w http.ResponseWriter, r *http.Request) {
	user, err := app.JwtUser(r.Context())
	if err != nil {
		app.HandleError(w, r, AppErr{wstack(err), 401}, HandlerOpts{View: true})
		return
	}
	page := PageContext{
		Username: template.HTML(user.Name),
		Title:    template.HTML(app.Name),
	}

	app.Render(w, r, "splash", page)
}

func (app App) AdminView(w http.ResponseWriter, r *http.Request) {
	user, err := app.JwtUser(r.Context())
	if err != nil {
		app.HandleError(w, r, AppErr{wstack(err), 500}, HandlerOpts{})
	}

	var users []User
	err = app.Db.All(&users)
	if err != nil {
		app.HandleError(w, r, AppErr{wstack(err), 500}, HandlerOpts{})
	}

	for i, _ := range users {
		users[i].Pass = ""
	}

	page := PageContext{
		Users:    users,
		Username: template.HTML(user.Name),
		Title:    template.HTML(app.Name),
	}

	app.Render(w, r, "admin", page)
}

func (app App) AdminPost(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		err := AppErr{wstack(err), 500}
		app.LogError(err)
		ctx := context.WithValue(r.Context(), "error", err)
		app.AdminView(w, r.WithContext(ctx))
		return
	}

	method := r.FormValue("_method")
	username := r.FormValue("username")
	password := r.FormValue("password")
	admin := r.FormValue("admin")

	app.LogDebug(fmt.Sprintf("UserPost - [user, admin] = [%s, %s]", username, admin))

	var user *User
	if method != "update" {
		user, err = newUser(username, password)
		if err != nil {
			app.LogDebug("UserPost - newUser: " + err.Error())
			ctx := context.WithValue(r.Context(), "NewUserError", AppErr{err, 400})
			app.AdminView(w, r.WithContext(ctx))
			return
		}
	} else {
		user = &User{}
		err = app.Db.One("Name", username, user)
		if err != nil {
			app.LogDebug("UserPost - getUser: " + err.Error())
			ctx := context.WithValue(r.Context(), "UpdateUserError", AppErr{err, 400})
			app.AdminView(w, r.WithContext(ctx))
			return
		}
	}

	user.Admin = admin == "on"
	if err = app.Db.Save(user); err != nil {
		err := AppErr{wstack(err), 500}
		app.LogError(err)
		ctx := context.WithValue(r.Context(), "error", err)
		app.AdminView(w, r.WithContext(ctx))
	}

	app.AdminView(w, r)
}

func (app App) Render(w http.ResponseWriter, r *http.Request, view string, p PageContext) {
	var renderers map[string]safed.Renderer
	if app.Debug {
		renderers = safed.InitRenderers(rice.MustFindBox("views"), "base.tmpl")
	} else {
		renderers = app.Renderers
	}

	ctx := r.Context()
	error, ok := ctx.Value("NewUserError").(AppErr)
	if ok {
		p.NewUserError = error.Error()
	}

	error, ok = ctx.Value("UpdateUserError").(AppErr)
	if ok {
		p.UpdateUserError = error.Error()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r, ok := renderers[view]; !ok {
		log.Fatal(wstack(fmt.Errorf("Could not find view renderer %s", view)))
	} else {
		r.Render(w, p)
	}
}
