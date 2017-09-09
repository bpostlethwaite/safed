package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/asdine/storm"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type ServerSuite struct {
	server *httptest.Server
	app    *App
	dbfile string
	suite.Suite
}

func (suite ServerSuite) login(user, pass string) *http.Response {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	form := url.Values{}
	form.Add("username", user)
	form.Add("password", pass)
	req, err := http.NewRequest(
		"POST", suite.server.URL+"/login", strings.NewReader(form.Encode()),
	)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	return res
}

func tempDbFile() string {
	f, _ := ioutil.TempFile("", "safed-test-db-")
	f.Close()
	os.Remove(f.Name())
	return f.Name()
}

func (suite *ServerSuite) SetupTest() {
	suite.dbfile = tempDbFile()
	db, err := storm.Open(suite.dbfile)
	if err != nil {
		panic("cannot open db: " + err.Error())
	}

	suite.app = &App{
		Auth:   jwtauth.New("HS256", []byte("xxxxxxxxxxxxxxxxxxxxxxxx"), nil),
		Db:     db,
		Debug:  true,
		Domain: "safed",
		Https:  false,
		Name:   "safed-test",
	}

	logger := logrus.New()
	logger.Formatter = &logrus.JSONFormatter{
		// disable, as we set our own
		DisableTimestamp: true,
	}
	suite.app.Logger = logger
	if suite.app.Debug {
		suite.app.Logger.SetLevel(logrus.DebugLevel)
	}

	server := httptest.NewServer(SafedRouter(*suite.app))
	suite.server = server
}

func (suite *ServerSuite) injectDbUser(username, password string) string {
	user, err := newUser(username, password)
	if err != nil {
		panic("newUser() Failed generating initial Admin account")
	}

	if err = suite.app.Db.Save(user); err != nil {
		panic(err)
	}

	return user.ID
}

func (suite *ServerSuite) TearDownTest() {

	// Close database and remove file.
	defer os.Remove(suite.dbfile)
	suite.app.Db.Close()
}

func (suite *ServerSuite) TestLoginJwt() {
	userId := suite.injectDbUser("hodor", "rodohodor")

	r := suite.login("hodor", "rodohodor")
	suite.Equal(http.StatusSeeOther, r.StatusCode)

	cookies := r.Cookies()
	suite.Equal(1, len(cookies))

	jwtCookie := cookies[0]
	jwtToken := jwtCookie.Value

	t, err := suite.app.Auth.Decode(jwtToken)
	if err != nil {
		suite.FailNow("Could not decode token %s", jwtToken)
	}

	claims := jwtauth.Claims(t.Claims.(jwt.MapClaims))

	iss, _ := claims.Get("iss")
	suite.Equal("safed", iss.(string))
	subi, _ := claims.Get("subi")
	suite.Equal(userId, subi.(string))
	subn, _ := claims.Get("subn")
	suite.Equal(userId, subn.(string))
	admin, _ := claims.Get("admin")
	suite.Equal(false, admin.(bool))
	exp, _ := claims.Get("exp")
	suite.True(float64(jwtauth.EpochNow()) < exp.(float64))
	iat, _ := claims.Get("iat")
	suite.True(float64(jwtauth.EpochNow()) >= iat.(float64))

}

func TestServerSuite(t *testing.T) {
	testSuite := new(ServerSuite)
	suite.Run(t, testSuite)
}
