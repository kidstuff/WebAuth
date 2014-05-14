package mgoauth

import (
	"github.com/kidstuff/WebAuth/auth"
	"labix.org/v2/mgo"
	"testing"
)

func TestUserManager(t *testing.T) {
	dbsess, err := mgo.Dial("localhost")
	if err != nil {
		t.Skip("cannot connect to MongoDB")
	}
	defer dbsess.Close()

	db := dbsess.DB("mgoauth_test")
	defer db.DropDatabase()

	var gmngr auth.GroupManager = NewMgoGroupManager(db)
	var mngr auth.UserManager = NewMgoUserManager(db, gmngr)

	u1, err := mngr.AddUser("test1@open-vn.org", "password123", true)
	if err != nil {
		t.Fatal("Failed to insert new user:", err)
	}

	u2, err := mngr.AddUserDetail("test2@open-vn.org", "password123", true,
		&auth.UserInfo{FirstName: "Nguyen"}, []string{"test"})
	if err != nil {
		t.Fatal("Failed to insert new user with detail:", err)
	}

	_, err = mngr.FindUser(u1.Id)
	if err != nil {
		t.Fatal("Failed to get user by Id", err)
	}

	_, err = mngr.FindUserByEmail(u2.Email)
	if err != nil {
		t.Fatal("Failed to get user by Email", err)
	}

	// _, err := mngr.AddUser("test1@open-vn.org", "password123", true)
	// if err != auth.ErrDuplicateEmail {
	// 	t.Fatal("Failed to check duplicate email")
	// }

	_, err = mngr.ValidateUser("test1@open-vn.org", "password123")
	if err != nil {
		t.Fatal("Failed to Validate user", err)
	}

	token, err := mngr.Login(u1.Id, 300)
	if err != nil {
		t.Fatal("Failed to Login", err)
	}

	u1, err = mngr.GetUser(token)
	if err != nil {
		t.Fatal("Failed to GetUser", err)
	}
}
