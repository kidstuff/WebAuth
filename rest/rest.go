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
}
