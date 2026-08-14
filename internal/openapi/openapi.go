// Package openapi отдаёт OpenAPI-спеку (/v3/api-docs) и Swagger UI
// (/swagger-ui.html) - те же пути, что и springdoc-openapi в Java NCANode.
// Спека - статичный JSON, сконвертированный из openapi.yml оригинального
// NCANode и обрезанный до реально реализованных в NCANode-Go actuator-путей;
// paths/schemas 1:1 совпадают с Go DTO (internal/dto), так как и то, и
// другое отражает один и тот же HTTP-контракт.
//
// Ассеты Swagger UI (static/) - файлы из webjar org.webjars:swagger-ui:5.11.8
// (та же версия, что тянет springdoc-openapi в Java-версии, лицензия
// Apache-2.0), завёрнуты в бинарник целиком - без обращения к CDN в рантайме.
package openapi

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
)

//go:embed openapi.json
var spec []byte

//go:embed static
var staticFiles embed.FS

const swaggerUIHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>NCANode-Go API</title>
  <link rel="icon" href="/swagger-ui/favicon-32x32.png">
  <link rel="stylesheet" href="/swagger-ui/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/swagger-ui/swagger-ui-bundle.js"></script>
  <script src="/swagger-ui/swagger-ui-standalone-preset.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: '/v3/api-docs',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
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

	assets, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err) // embed.FS с прописанным static/ - гарантированно валиден на этапе компиляции
	}
	s.HandleRaw("GET /swagger-ui/", http.StripPrefix("/swagger-ui/", http.FileServerFS(assets)).ServeHTTP)
}
