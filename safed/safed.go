package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	rice "github.com/GeertJohan/go.rice"
	"github.com/asdine/storm"
	"github.com/bpostlethwaite/safed"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	ServerError = iota
	NewUserError
	UpdateUserError
	AuthError
)

type App struct {
	Name         string
	SigningKey   []byte
	Db           *storm.DB
	Domain       string
	Https        bool
	Logger       *logrus.Logger
	LogMiddeware func(http.Handler) http.Handler
	Debug        bool
	Renderers    map[string]safed.Renderer
	Auth         *jwtauth.JwtAuth
}

var wstack = errors.WithStack
var wmsg = errors.WithMessage

type AppError struct {
	error
	Code int
}

func (err AppError) ServerError() bool {
	return err.Code == ServerError
}

func (err AppError) NewUserError() bool {
	return err.Code == NewUserError
}

func (err AppError) UpdateUserError() bool {
	return err.Code == UpdateUserError
}

func (err AppError) AuthError() bool {
	return err.Code == AuthError
}

func (app App) LogError(err error) {
	if app.Logger == nil {
		return
	}
	app.Logger.Error(safed.Stack(err))
}

func (app App) LogDebug(msg string) {
	if app.Debug && app.Logger != nil {
		app.Logger.Debug(msg)
	}
}

func (app *App) Init() error {
	logger := logrus.New()
	logger.Formatter = &logrus.JSONFormatter{
		// disable, as we set our own
		DisableTimestamp: true,
	}
	app.Logger = logger
	if app.Debug {
		app.Logger.SetLevel(logrus.DebugLevel)
	}

	app.LogMiddeware = safed.NewStructuredLogger(logger)

	if !app.Debug {
		app.Renderers = safed.InitRenderers(rice.MustFindBox("views"), "base.tmpl")
	}

	return app.Db.Init(&User{})
}

func main() {
	secret := os.Getenv("SAFED_KEY")
	if len(secret) < 15 {
		log.Fatal("SAFED_KEY must be greater than 15 digits")
	}
	signingKey := []byte(secret)

	domain := os.Getenv("SAFED_DOMAIN")
	if !strings.Contains(domain, ".") {
		log.Fatal("SAFED_DOMAIN must be a valid domain")
	}

	debug := false
	if os.Getenv("SAFED_DEBUG") == "1" {
		debug = true
	}

	HTTPS := true
	if os.Getenv("SAFED_HTTP_ONLY") == "1" {
		HTTPS = false
	}

	port := os.Getenv("SAFED_PORT")
	if port == "" {
		port = "3335"
	}

	db, err := storm.Open("safe.db")
	if err != nil {
		log.Fatal(wmsg(err, "Couldn't open safe.db"))
	}
	defer db.Close()

	app := App{
		Auth:   jwtauth.New("HS256", signingKey, nil),
		Db:     db,
		Debug:  debug,
		Domain: domain,
		Https:  HTTPS,
		Name:   "safed",
	}

	err = app.Init()
	if err != nil {
		log.Fatal(wmsg(err, "app.Init failed"))
	}

	// Ensure there is at least 1 admin user.
	adminOpt := flag.String("admin", "", "Set admin user.")
	flag.Parse()
	if err := app.Db.Find("Admin", true, &[]User{}); err != nil {

		if err != storm.ErrNotFound {
			log.Fatal(wmsg(wstack(err), "Err encountered looking up Admin from DB"))
		}

		if adminOpt == nil {
			log.Fatal(errors.New("You must set an admin user using the " +
				"'--admin user:pass' option. This only needs performing once"))
		}

		namepass := strings.Split(*adminOpt, ":")
		if len(namepass) != 2 {
			log.Fatal(errors.New("Admin option formatted incorrectly. " +
				"Please ensure it is user:pass"))
		}

		user, err := newUser(namepass[0], namepass[1])
		if err != nil {
			log.Fatal(wmsg(err, "newUser() Failed generating initial Admin account"))
		}

		user.Admin = true
		if err = app.Db.Save(user); err != nil {
			log.Fatal(err)
		}
	}

	addr := fmt.Sprintf(":%s", port)
	fmt.Printf("Starting server on %v\n", addr)
	fmt.Printf("Https is %t\n", app.Https)
	fmt.Printf("Debug is %t\n", app.Debug)
	err = http.ListenAndServe(addr, SafedRouter(app))
	if err != nil {
		log.Fatal(err)
	}
}

func SafedRouter(app App) http.Handler {
	r := chi.NewRouter()
	if app.LogMiddeware != nil {
		r.Use(app.LogMiddeware)
	}

	// Protected Views
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(app.Auth))
		r.Use(app.Authenticator)
		r.Get("/", app.SplashView)
		r.Post("/logout", app.Logout)
	})

	// Admin Protected Views
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(app.Auth))
		r.Use(app.AdminAuthenticator)
		r.Get("/admin", app.AdminView)
		r.Post("/admin", app.AdminPost)
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(app.Auth))

		safed.FileServer(r, "/static", rice.MustFindBox("static").HTTPBox())
		r.Get("/login", app.LoginView)
		r.Post("/login", app.Login)
	})

	return r
}

func (app *App) JwtUser(ctx context.Context) (*User, error) {
	token, claims, err := jwtauth.FromContext(ctx)
	if err != nil {
		return nil, wstack(err)
	}
	if token == nil {
		return nil, wstack(fmt.Errorf("Token not extracted from request"))
	}

	userID, ok := claims.Get("subi")
	if !ok {
		return nil, wstack(fmt.Errorf("No subi field in claims"))
	}

	var user User
	err = app.Db.One("ID", userID, &user)
	if err != nil {
		return nil, wstack(wmsg(err, "Couldn't find userID "+userID.(string)))
	}

	return &user, nil
}
