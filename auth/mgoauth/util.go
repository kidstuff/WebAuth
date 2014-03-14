package mgoauth

import (
	"github.com/kidstuff/WebAuth/auth"
	"labix.org/v2/mgo/bson"
	"time"
)

type LoginState struct {
	On        time.Time
	Threshold time.Duration
	UserId    bson.ObjectId
	Token     string `bson:"_id"`
}

// getId returns bson.ObjectId form given id.
// id must be a valid bson.ObjectId or a valid ObjectIdHex
func getId(id interface{}) (bson.ObjectId, error) {
	oid, ok := id.(bson.ObjectId)
	if ok {
		return oid, nil
	}

	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return "", auth.ErrInvalidId
	}

	return bson.ObjectIdHex(sid), nil
}
