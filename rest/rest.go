package rest

import (
	"github.com/gorilla/mux"
	"time"
)

var (
	OnlineThreshold = time.Hour
)

func Handler(router *mux.Router) {
	router.HandleFunc("/tokens", GetToken)
	router.HandleFunc("/signup", SignUp)
	router.HandleFunc("/active/{id}", ActiveAccount)
	router.HandleFunc("/profile/{id}/info", UserInfoUpdate)
	router.HandleFunc("/profile/{id}/change-password", PasswordUpdate)
}
