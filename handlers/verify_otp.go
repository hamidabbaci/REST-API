package handlers

import (
	"encoding/json"
	"net/http"
	"time"
)

func VerifyOTPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username string `json:"username"`
		OTP      string `json:"otp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	otpStore.RLock()
	otpData, exists := otpStore.data[data.Username]
	otpStore.RUnlock()

	if !exists {
		http.Error(w, "OTP not found", http.StatusUnauthorized)
		return
	}

	if time.Now().After(otpData.Expire) {
		http.Error(w, "OTP expired", http.StatusUnauthorized)
		return
	}

	if otpData.Code != data.OTP {
		http.Error(w, "OTP invalid", http.StatusUnauthorized)
		return
	}

	otpStore.Lock()
	delete(otpStore.data, data.Username)
	otpStore.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "OTP verified successfully",
	})
}
