package rest

import (
	"errors"
	"github.com/gorilla/mux"
	"github.com/kidstuff/WebAuth/auth"
	"github.com/kidstuff/WebUtil/response"
	"net/http"
)

func getUserByIdAndWriteIfError(rw http.ResponseWriter, req *http.Request) (*auth.User, auth.UserManager, error) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	vars := mux.Vars(req)
	idStr := vars["id"]
	if len(idStr) == 0 {
		response.BadRequestResponse(rw, &response.JSONErr{
			Code:        ErrCodeInvalidId,
			Message:     "Missing 'id' from request",
			Description: "The request URI must be /active/{id}?code=xxxx",
		})
		return nil, nil, errors.New("rest: Missing 'id' from request")
	}

	userMngr, err := auth.Provider().OpenUserMngr(req)
	if err != nil {
		response.InternalErrorResponse(rw, &response.JSONErr{Message: err.Error()})
		return nil, nil, err
	}

	u, err := userMngr.FindUser(idStr)
	if err != nil {
		response.ErrorResponse(rw, http.StatusPreconditionFailed, &response.JSONErr{
			Code:    ErrCodeNotExistId,
			Message: "Account not exists",
		})
		return nil, userMngr, err
	}

	return u, userMngr, nil
}
