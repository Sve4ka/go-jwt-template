package models

type UserBase struct {
	Name    string `json:"name"`
	SurName string `json:"sur_name"`
	Email   string `json:"email"`
}

type User struct {
	ID int `json:"id"`
	UserBase
}

type UserCreate struct {
	UserBase
	PWD string `json:"pwd"`
}

type UserLogin struct {
	Email string `json:"email"`
	PWD   string `json:"password"`
}

type UserChangePWD struct {
	ID     int    `json:"id"`
	NewPWD string `json:"newPassword"`
}
