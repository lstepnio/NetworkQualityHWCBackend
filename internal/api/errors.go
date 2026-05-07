package api

import (
	"encoding/json"
	"net/http"
)

type ErrorBody struct {
	Error   string        `json:"error"`
	Details []ErrorDetail `json:"details,omitempty"`
}

type ErrorDetail struct {
	Path string `json:"path"`
	Msg  string `json:"msg"`
}

func writeError(w http.ResponseWriter, status int, msg string, details ...ErrorDetail) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorBody{Error: msg, Details: details})
}
