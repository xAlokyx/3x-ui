package model

// User represents a user account in the 3x-ui panel.
type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username"`
	Password string `json:"password"`
	LimitIP  int64  `json:"limit_ip" gorm:"column:limit_ip;default:0"`
}
