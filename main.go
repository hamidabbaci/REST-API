package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Structs

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type OTPData struct {
	Code   string
	Expire time.Time
}

// Global variables

var db *sql.DB
var jwtKey = []byte("my_super_secret_key")

var otpStore = struct {
	sync.RWMutex
	data map[string]OTPData
}{
	data: make(map[string]OTPData),
}

// Register Handler

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(user.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(
		"INSERT INTO users(username, email, password) VALUES (?,?,?)",
		user.Username,
		user.Email,
		string(hashedPassword),
	)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rand.Seed(time.Now().UnixNano())
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))

	otpStore.Lock()
	otpStore.data[user.Username] = OTPData{
		Code:   otp,
		Expire: time.Now().Add(2 * time.Minute),
	}
	otpStore.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User registered successfully",
		"otp":     otp,
	})
}

// Verify OTP

func verifyOTPHandler(w http.ResponseWriter, r *http.Request) {
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

// Login + JWT

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var hashedPassword string
	err := db.QueryRow(
		"SELECT password FROM users WHERE username = ?",
		data.Username,
	).Scan(&hashedPassword)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword),
		[]byte(data.Password),
	)
	if err != nil {
		http.Error(w, "Wrong username or password", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": data.Username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "login successful",
		"token":   tokenString,
	})
}

func forgetPasswordHandler(w http.ResponseWriter, r *http.Request) {
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
	err := db.QueryRow(
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

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
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
	_, err = db.Exec(
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

// Main

func main() {
	var err error

	// MySQL روی Docker → پورت 8077
	dsn := "appuser:apppass@tcp(127.0.0.1:8077)/myapp?parseTime=true"

	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("DB error:", err)
	}

	fmt.Println("Connected to MySQL successfully")

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/verify_otp", verifyOTPHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/forget_password", forgetPasswordHandler)
	http.HandleFunc("/reset_password", resetPasswordHandler)
	// API روی 8080
	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
