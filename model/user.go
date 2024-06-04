package model

type User struct {
	Email       string   `json:"email"`
	Password    string   `json:"password"`
	Role        string   `json:"role"`
	TeamMembers []string `json:"team_members"`
}
