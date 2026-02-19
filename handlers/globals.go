package handlers

//گلوبال جمعی هست برای اینکه همه فایل ها بتونن ازش استفاده کنن
import (
	"database/sql"
	"sync"
	"time"
)

type OTPData struct {
	Code   string
	Expire time.Time
}

// Global variables

var DB *sql.DB
var jwtKey = []byte("my_super_secret_key")

var otpStore = struct {
	sync.RWMutex
	data map[string]OTPData
}{
	data: make(map[string]OTPData),
}
