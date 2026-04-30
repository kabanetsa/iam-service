package model

import "time"

type Session struct {
	ID           string    `redis:"id"`
	UserID       string    `redis:"user_id"`
	RefreshToken string    `redis:"refresh_token"`
	DeviceID     string    `redis:"device_id"`
	IPAddress    string    `redis:"ip"`
	UserAgent    string    `redis:"user_agent"`
	CreatedAt    time.Time `redis:"created_at"`
	ExpiresAt    time.Time `redis:"expires_at"`
}
