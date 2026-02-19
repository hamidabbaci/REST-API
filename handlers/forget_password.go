package handlers

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

func ForgetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	//chek user exist yes or no?
	var exists string
	err := DB.QueryRow(
		"SELECT username FROM users WHERE username = ?",
		data.Username,
	).Scan(&exists)

	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	//create new Otp
	rand.Seed(time.Now().UnixNano())
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))

	//otp save in engza
	otpStore.Lock()
	otpStore.data[data.Username] = OTPData{
		Code:   otp,
		Expire: time.Now().Add(2 * time.Minute),
	}
	otpStore.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Otp verified successfully",
		"otp":     otp,
	})
}
