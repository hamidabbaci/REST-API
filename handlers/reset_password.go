package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username    string `json:"username"`
		OTP         string `json:"otp"`
		NewPassword string `json:"new_password"`
	}

	// 1️⃣ خواندن JSON
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 2️⃣ گرفتن OTP از رم
	otpStore.RLock()
	otpData, exists := otpStore.data[data.Username]
	otpStore.RUnlock()

	if !exists {
		http.Error(w, "OTP not found", http.StatusUnauthorized)
		return
	}

	// 3️⃣ چک انقضا
	if time.Now().After(otpData.Expire) {
		http.Error(w, "OTP expired", http.StatusUnauthorized)
		return
	}

	// 4️⃣ چک خود کد
	if otpData.Code != data.OTP {
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	// 5️⃣ هش کردن پسورد جدید
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(data.NewPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// 6️⃣ آپدیت پسورد در دیتابیس
	_, err = DB.Exec(
		"UPDATE users SET password = ? WHERE username = ?",
		string(hashedPassword),
		data.Username,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// 7️⃣ پاک کردن OTP
	otpStore.Lock()
	delete(otpStore.data, data.Username)
	otpStore.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successful",
	})
}
