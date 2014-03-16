package rest

import (
	"github.com/gorilla/mux"
)

func Handler(router *mux.Router) {
	router.HandleFunc("/tokens", GetToken)
}
