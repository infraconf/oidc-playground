package public

import (
	"embed"
	"html/template"
	"io"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

var authorizeTemplate = template.Must(template.New("authorize.html").Funcs(template.FuncMap{
	"scopeList": func(scope string) []string {
		if scope == "" {
			return nil
		}

		return strings.Fields(scope)
	},
	"initials": func(name string) string {
		parts := strings.Fields(name)
		if len(parts) == 0 {
			return "?"
		}

		var out string
		for _, part := range parts {
			if part == "" {
				continue
			}
			out += strings.ToUpper(part[:1])
			if len(out) >= 2 {
				break
			}
		}

		if out == "" {
			return "?"
		}

		return out
	},
}).ParseFS(templateFS, "templates/authorize.html"))

func RenderAuthorize(w io.Writer, data any) error {
	return authorizeTemplate.Execute(w, data)
}
