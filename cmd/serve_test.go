package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMemoryAPIMergeRetainsAuthentication(t *testing.T) {
	handler := authMiddleware("fixture", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		path, token string
		want        int
	}{{"/health", "", 204}, {"/info", "", 401}, {"/scan", "Bearer wrong", 401}, {"/scan", "Bearer fixture", 204}} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.Header.Set("Authorization", tc.token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.path, response.Code, tc.want)
		}
	}
}
