package main

import (
	"encoding/json"
	"net/http"
)

// User represents a public view of a user.
/*type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}*/

// isAdmin checks if the current request has admin rights.
// (Replace this with your actual authorization logic.)
/*func isAdmin(r *http.Request) bool {
	cookie, err := r.Cookie("admin")
	if err != nil {
		return false
	}
	return cookie.Value == "true"
}*/

// GetUsersHandler retrieves all users from the DB and returns them as JSON.
func GetUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Check for admin authorization.
	/*if !isAdmin(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}*/

	rows, err := db.Query("SELECT id, username FROM users")
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username); err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}
