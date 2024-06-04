package controller

import (
	"backend/utils"
	"encoding/json"
	"net/http"
)

type ResendVerificationRequest struct {
	Email string `json:"email"`
}

func ResendVerificationHandler(w http.ResponseWriter, r *http.Request) {
	var req ResendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	err := utils.ResendVerificationEmail(req.Email)
	if err != nil {
		http.Error(w, "Failed to resend verification email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Verification email sent successfully"))
}
