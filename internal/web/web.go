// Package web holds the server-rendered pages of the authorization server: the
// login form and the consent screen. They are embedded in the binary so that a
// deployment cannot start with missing templates.
package web

import (
	"embed"
	"fmt"
	"html/template"
)

//go:embed templates/*.html
var files embed.FS

// Page names accepted by Pages.
const (
	PageLogin   = "login.html"
	PageConsent = "consent.html"
	PageError   = "error.html"
)

// Pages maps a page name to a template set (layout plus that page's content).
// Each page gets its own set because every page defines the shared "content"
// block; a single set would fail with a duplicate definition.
type Pages map[string]*template.Template

// Templates parses the embedded pages.
func Templates() (Pages, error) {
	pages := make(Pages, 3)
	for _, name := range []string{PageLogin, PageConsent, PageError} {
		tmpl, err := template.ParseFS(files, "templates/layout.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("web: parse template %s: %w", name, err)
		}
		pages[name] = tmpl
	}
	return pages, nil
}

// Render writes a page using the shared layout. Rendering errors are returned so
// that the caller can decide between a 500 page and a protocol error.
func (p Pages) Render(w interface{ Write([]byte) (int, error) }, name string, data any) error {
	tmpl, ok := p[name]
	if !ok {
		return fmt.Errorf("web: unknown page %q", name)
	}
	return tmpl.ExecuteTemplate(w, "layout", data)
}
