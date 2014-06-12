package rest

import (
	"github.com/gorilla/mux"
	"github.com/kidstuff/WebAuth/auth"
	"time"
)

var (
	OnlineThreshold = time.Hour
)

func Handler(router *mux.Router) {
	router.HandleFunc("/tokens", GetToken)
	router.HandleFunc("/signup", SignUp)
	router.HandleFunc("/active/{id}", ActiveAccount)
	router.HandleFunc("/profiles", auth.OAuthHandleWrapper(UserList, []string{"admin"}, nil))
	router.HandleFunc("/profiles/{id}/info", UserInfoUpdate).Methods("PUT")
	router.HandleFunc("/profiles/{id}/info", UserInfoDetail).Methods("GET")
	router.HandleFunc("/profiles/{id}/change-password", PasswordUpdate)
}
