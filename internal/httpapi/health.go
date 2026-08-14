package httpapi

import "net/http"

type healthResponse struct {
	Status string `json:"status"`
}

// RegisterHealth регистрирует /actuator/health - та же форма ответа, что
// отдаёт Spring Boot Actuator в Java NCANode ({"status":"UP"}).
func (s *Server) RegisterHealth() {
	s.HandleRaw("GET /actuator/health", func(w http.ResponseWriter, r *http.Request) {
		s.writeJSON(w, http.StatusOK, healthResponse{Status: "UP"})
	})
}
