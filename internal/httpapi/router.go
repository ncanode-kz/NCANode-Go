package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// Server - тонкая обёртка над http.ServeMux с единым JSON-конвертом ошибок
// (аналог глобального RuntimeException handler-а в Java NCANode) и recover
// от паник в хендлерах.
type Server struct {
	mux   *http.ServeMux
	debug bool
}

func New(debug bool) *Server {
	return &Server{mux: http.NewServeMux(), debug: debug}
}

func (s *Server) Handler() http.Handler { return s.mux }

// HandleRaw регистрирует хендлер без JSON-декодирования запроса (например
// для health-проверок).
func (s *Server) HandleRaw(pattern string, fn func(w http.ResponseWriter, r *http.Request)) {
	s.mux.HandleFunc(pattern, fn)
}

// Handle регистрирует JSON-эндпоинт: декодирует тело запроса в Req, вызывает
// fn, сериализует Resp как 200 или ошибку в единый конверт
// {status,message,details?} (details только при debug=true, как
// NCANODE_DEBUG в Java).
func Handle[Req any, Resp any](s *Server, pattern string, fn func(r *http.Request, req Req) (Resp, error)) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		defer s.recoverPanic(w, r)

		var req Req
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				s.writeError(w, ClientError("malformed JSON request body", err))
				return
			}
		}

		resp, err := fn(r, req)
		if err != nil {
			s.writeError(w, err)
			return
		}

		s.writeJSON(w, http.StatusOK, resp)
	})
}

func (s *Server) recoverPanic(w http.ResponseWriter, r *http.Request) {
	if rec := recover(); rec != nil {
		slog.Error("panic in handler", "path", r.URL.Path, "recover", rec)
		s.writeError(w, ServerError(fmt.Sprintf("internal error: %v", rec), nil))
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, statusCode int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("failed to encode json response", "error", err)
	}
}

type errorEnvelope struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	var appErr *AppError
	if !errors.As(err, &appErr) {
		appErr = &AppError{StatusCode: http.StatusInternalServerError, Msg: err.Error()}
	}

	env := errorEnvelope{Status: appErr.StatusCode, Message: appErr.Msg}

	if s.debug {
		if appErr.Cause != nil {
			env.Details = appErr.Cause.Error()
		} else {
			env.Details = appErr.Msg
		}
	}

	s.writeJSON(w, appErr.StatusCode, env)
}
