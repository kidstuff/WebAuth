package gaeauth

import (
	"appengine/datastore"
	"github.com/kidstuff/WebAuth/auth"
)

func getId(id interface{}) (*datastore.Key, error) {
	oid, ok := id.(*datastore.Key)
	if ok {
		return oid, nil
	}

	sid, ok := id.(string)
	if !ok {
		return nil, auth.ErrInvalidId
	}

	oid, err := datastore.DecodeKey(sid)
	if err != nil {
		return nil, err
	}

	return oid, nil
}
