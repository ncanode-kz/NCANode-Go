// Package openapi отдаёт OpenAPI-спеку (/v3/api-docs) и Swagger UI
// (/swagger-ui.html) - те же пути, что и springdoc-openapi в Java NCANode.
// Спека - статичный JSON, сконвертированный из openapi.yml оригинального
// NCANode и обрезанный до реально реализованных в NCANode-Go actuator-путей;
// paths/schemas 1:1 совпадают с Go DTO (internal/dto), так как и то, и
// другое отражает один и тот же HTTP-контракт.
package openapi

import (
	_ "embed"
	"net/http"

	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
)

//go:embed openapi.json
var spec []byte

const swaggerUIHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>NCANode-Go API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: '/v3/api-docs',
      dom_id: '#swagger-ui',
    });
  </script>
</body>
</html>
`

func RegisterRoutes(s *httpapi.Server) {
	s.HandleRaw("GET /v3/api-docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(spec) //nolint:errcheck
	})

	s.HandleRaw("GET /swagger-ui.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(swaggerUIHTML)) //nolint:errcheck
	})
}
