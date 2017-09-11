package safed

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	rice "github.com/GeertJohan/go.rice"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/pkg/errors"
)

type Renderer struct {
	Template *template.Template
	Base     string
}

func (r Renderer) Render(w http.ResponseWriter, p interface{}) {
	r.Template.ExecuteTemplate(w, r.Base, p)
}

func InitRenderers(tbox *rice.Box, base string) map[string]Renderer {

	renderers := make(map[string]Renderer)
	baseStr, err := tbox.String(base)
	if err != nil {
		log.Fatal(errors.WithStack(err))
	}

	components := [][]string{}
	views := [][]string{}

	tbox.Walk("", func(p string, i os.FileInfo, e error) error {
		if i.IsDir() {
			return nil
		}

		if p == base {
			return nil
		}

		s, e := tbox.String(p)
		if e != nil {
			log.Fatalf("Failed to load template: %s\n%s\n", p, e)
		}

		dir, f := path.Split(p)
		name := f[:len(f)-len(".tmpl")]
		if dir == "" {
			views = append(views, []string{name, s})
		} else {
			components = append(components, []string{name, s})
		}

		return nil
	})

	for _, ps := range views {
		name := ps[0]
		view := ps[1]
		t := template.Must(
			template.Must(template.New(name).Parse(baseStr)).Parse(view),
		)

		for _, cs := range components {
			component := cs[1]
			template.Must(t.Parse(component))
		}

		renderers[name] = Renderer{t, base[:len(base)-len(".tmpl")]}
	}

	return renderers
}

func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit URL parameters.")
	}

	fs := http.StripPrefix(path, http.FileServer(root))

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}

func ValidateToken(ctx context.Context) (jwtauth.Claims, error) {
	token, claims, err := jwtauth.FromContext(ctx)
	if err != nil {
		return claims, errors.WithStack(err)
	}

	// jwt-auth automatically handles expirey using the 'exp' claim
	if token == nil || !token.Valid {
		return claims, errors.New("Invalid token")
	}

	return claims, nil
}
