package controller

import (
	"backend/model"
	"backend/utils"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user model.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Authenticate user with Firebase Authentication
	u, err := utils.FirebaseAuth.GetUserByEmail(context.Background(), user.Email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		log.Printf("Failed to get user: %v\n", err)
		return
	}

	if !u.EmailVerified {
		http.Error(w, "Email not verified", http.StatusUnauthorized)
		log.Printf("Email not verified for user: %v\n", user.Email)
		return
	}

	// Retrieve user's data from Firebase Database
	var userData model.User
	err = utils.FirebaseDB.NewRef("users/"+u.UID).Get(context.Background(), &userData)
	if err != nil {
		http.Error(w, "Failed to retrieve user data", http.StatusInternalServerError)
		log.Printf("Failed to retrieve user data: %v\n", err)
		return
	}

	// Set custom claims including role from the request body
	claims := map[string]interface{}{
		"role":    userData.Role,
		"user_id": user.Email, // Using email as the user_id
	}

	// Generate custom token with claims
	token, err := utils.FirebaseAuth.CustomTokenWithClaims(context.Background(), user.Email, claims)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		log.Printf("Failed to create custom token: %v\n", err)
		return
	}

	// Set token expiration time (e.g., 1 hour)
	expirationTime := time.Now().Add(time.Hour).Unix()

	// Create the response payload
	response := map[string]interface{}{
		"token":       token,
		"expires":     expirationTime,
		"role":        userData.Role,
		"user_id":     user.Email,
		"teamMembers": userData.TeamMembers, // Assuming TeamMembers is already fetched
	}
	// Return the token in the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		log.Printf("Failed to encode response: %v\n", err)
	}
}
