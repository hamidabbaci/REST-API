package main

import (
	"database/sql"
	"fmt"
	"gotest1/handlers"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

// Main

func main() {
	var err error

	// MySQL روی Docker → پورت 8077
	dsn := "appuser:apppass@tcp(127.0.0.1:8077)/myapp?parseTime=true"

	handlers.DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer handlers.DB.Close()

	if err = handlers.DB.Ping(); err != nil {
		log.Fatal("DB error:", err)
	}

	fmt.Println("Connected to MySQL successfully")

	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/verify_otp", handlers.VerifyOTPHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/forget_password", handlers.ForgetPasswordHandler)
	http.HandleFunc("/reset_password", handlers.ResetPasswordHandler)
	// API روی 8080
	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
