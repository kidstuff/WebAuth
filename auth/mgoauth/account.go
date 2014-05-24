package mgoauth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/base64"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/kidstuff/WebAuth/auth"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"log"
	"time"
)

var (
	ErrNoResult = errors.New("mgoauth: no result")
)

type MgoUserManager struct {
	OnlineThreshold time.Duration
	UserColl        *mgo.Collection
	LoginColl       *mgo.Collection
	Formater        auth.FormatChecker
	GroupMngr       auth.GroupManager
}

// NewMgoUserManager create new MgoUserManager with UserColl name "mgoauth_user"
// and LoginColl name "mgoauth_login" with default 5 minutes for OnlineThreshold.
func NewMgoUserManager(db *mgo.Database, groupMngr auth.GroupManager) *MgoUserManager {
	mngr := &MgoUserManager{
		UserColl:        db.C("mgoauth_user"),
		LoginColl:       db.C("mgoauth_login"),
		OnlineThreshold: time.Minute * 5,
		GroupMngr:       groupMngr,
	}

	mngr.Formater, _ = auth.NewSimpleChecker(9)

	return mngr
}

// GroupManager returns the GroupManager.
func (m *MgoUserManager) GroupManager() auth.GroupManager {
	return m.GroupMngr
}

// newUser create an *auth.User without save it to database.
// Its set an BSON ObjectID and check email,password.
func (m *MgoUserManager) newUser(email, pwd string, app bool) (*auth.User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, auth.ErrInvalidEmail
	}

	if !m.Formater.PasswordValidate(pwd) {
		return nil, auth.ErrInvalidPassword
	}

	u := &auth.User{}
	u.Id = bson.NewObjectId()
	u.Email = email
	u.LastActivity = time.Now()
	u.Info.JoinDay = u.LastActivity

	p, err := auth.HashPwd(pwd)
	if err != nil {
		return nil, err
	}

	u.Pwd = p

	u.Approved = app
	return u, nil
}

// insertUser inserts User to database.
// the user with that email exist. Note that indexes musted create fo MongoDB.
func (m *MgoUserManager) insertUser(u *auth.User) error {
	err := m.UserColl.Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return auth.ErrDuplicateEmail
		}
		return err
	}

	return nil
}

// AddUser will generate user's Id and adds an user to database with email and password;
// If app is false, the user is waiting to be approved.
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) AddUser(email, pwd string, app bool) (*auth.User,
	error) {
	u, err := m.newUser(email, pwd, app)
	if err != nil {
		return nil, err
	}

	err = m.insertUser(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// AddUserDetail will generate user's Id and adds an user to database;
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) AddUserDetail(u *auth.User) (*auth.User, error) {
	u.Id = bson.NewObjectId()
	err := m.insertUser(u)
	return u, err
}

// UpdateUserDetail update user infomation specific by Id and Email field.
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) UpdateUserDetail(u *auth.User) error {
	oid, err := getId(u.Id)
	if err != nil {
		return err
	}

	return m.UserColl.Update(bson.M{
		"_id":   oid,
		"Email": u.Email,
	}, u)
}

// ChangePassword changes passowrd of user specify by id.
func (m *MgoUserManager) ChangePassword(id interface{}, pwd string) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}

	u := &auth.User{}
	err = m.UserColl.FindId(oid).One(&u)
	if err != nil {
		return err
	}

	p, err := auth.HashPwd(pwd)
	if err != nil {
		return err
	}

	return m.UserColl.UpdateId(oid, bson.M{
		"$set":  bson.M{"Pwd": p},
		"$push": bson.M{"OldPwd": u.OldPwd},
	})
}

// DeleteUserByEmail deletes an user from database base on the given id;
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) DeleteUser(id interface{}) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}

	return m.UserColl.RemoveId(oid)
}

// FindUser finds the user with the given id;
// Its returns an ErrNotFound if the user's id was not found.
func (m *MgoUserManager) FindUser(id interface{}) (*auth.User, error) {
	oid, err := getId(id)
	if err != nil {
		return nil, err
	}

	u := &auth.User{}
	err = m.UserColl.FindId(oid).One(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// FindUserByEmail like FindUser but receive an email
func (m *MgoUserManager) FindUserByEmail(email string) (*auth.User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, auth.ErrInvalidEmail
	}

	u := &auth.User{}
	err := m.UserColl.Find(bson.M{"Email": email}).One(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (m *MgoUserManager) findAllUser(offsetKey interface{}, limit int,
	filter bson.M) ([]*auth.User, error) {
	if limit == 0 {
		return nil, ErrNoResult
	}

	if filter == nil {
		filter = bson.M{}
	}

	if offsetKey != nil {
		oid, err := getId(offsetKey)
		if err == nil {
			filter["_id"] = bson.M{"$gt": oid}
		}
	}

	query := m.UserColl.Find(filter)
	var accounts []*auth.User
	if limit > 0 {
		query.Limit(limit)
		accounts = make([]*auth.User, 0, limit)
	} else {
		accounts = []*auth.User{}
	}

	err := query.All(&accounts)
	if err != nil {
		return nil, err
	}

	return accounts, nil
}

// FindAllUser finds and return a slice of user.
// offsetId, limit define which sub-sequence of matching users to return.
// Limit take an number of user per page; offsetId take the Id of the last
// user of the previous page.
func (m *MgoUserManager) FindAllUser(offsetId interface{}, limit int) (
	[]*auth.User, error) {
	return m.findAllUser(offsetId, limit, nil)
}

// FindAllUserOline finds and return a slice of current Loged user.
// See FindAllUser for the usage.
func (m *MgoUserManager) FindAllUserOnline(offsetId interface{}, limit int) (
	[]*auth.User, error) {
	return m.findAllUser(offsetId, limit, bson.M{
		"LastActivity": bson.M{"$lt": time.Now().Add(m.OnlineThreshold)},
	})
}

// ValidateUser validate user email and password.
// It returns the user infomations if the email and password is correct.
func (m *MgoUserManager) ValidateUser(email, pwd string) (*auth.User, error) {
	u, err := m.FindUserByEmail(email)
	if err != nil {
		return nil, err
	}

	pwdBytes := []byte(pwd)
	tmp := make([]byte, len(pwdBytes)+len(u.Pwd.Salt))
	copy(tmp, pwdBytes)
	tmp = append(tmp, u.Pwd.Salt...)
	if err := bcrypt.CompareHashAndPassword(u.Pwd.Hashed, tmp); err != nil {
		return nil, err
	}

	return u, nil
}

func (m *MgoUserManager) updateLastActivity(id bson.ObjectId) (*auth.User, error) {
	u := &auth.User{}
	err := m.UserColl.FindId(id).One(u)
	if err != nil {
		return nil, err
	}

	u.LastActivity = time.Now()
	// ??? should we ignore the error return here?
	err = m.UserColl.UpdateId(id, bson.M{
		"$set": bson.M{"LastActivity": u.LastActivity},
	})
	if err != nil {
		return nil, err
	}

	return u, nil
}

// GetUser gets the infomations and update the LastActivity of the current
// Loged user;
// It returns an error describes the first issue encountered, if any.
func (m *MgoUserManager) GetUser(token string) (*auth.User, error) {
	state := LoginState{}
	err := m.LoginColl.FindId(token).One(&state)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, auth.ErrNotLogged
		}
		return nil, err
	}

	if !state.ExpiredOn.After(time.Now()) {
		m.LoginColl.RemoveId(token)
	}

	return m.updateLastActivity(state.UserId)
}

// Login logs user in.
// IF stay lester than default OnlineThreshold user will stay in OnlineThreshold.
func (m *MgoUserManager) Login(id interface{}, stay time.Duration) (string, error) {
	if stay < m.OnlineThreshold {
		stay = m.OnlineThreshold
	}

	oid, err := getId(id)
	if err != nil {
		return "", err
	}

	state := LoginState{
		ExpiredOn: time.Now().Add(stay),
		UserId:    oid,
		Token: oid.Hex() + base64.URLEncoding.
			EncodeToString(securecookie.GenerateRandomKey(64)),
	}

	err = m.LoginColl.Insert(&state)
	if err != nil {
		return "", err
	}

	return state.Token, nil
}

// Logout logs the current user out.
func (m *MgoUserManager) Logout(token string) error {
	return m.LoginColl.RemoveId(token)
}

// ValidConfirmCode valid the code for specific key of the user specify by id.
// Re-generate or delete code for that key if need.
func (m *MgoUserManager) ValidConfirmCode(id interface{}, key, code string,
	regen, del bool) (bool, error) {
	user, err := m.FindUser(id)
	if err != nil {
		return false, err
	}

	if user.ConfirmCodes[key] == code {
		if del {
			delete(user.ConfirmCodes, key)
		}

		if regen {
			user.ConfirmCodes[key] = base64.URLEncoding.EncodeToString(securecookie.
				GenerateRandomKey(64))
		}

		m.UpdateUserDetail(user)
		return true, nil
	}

	return false, nil
}

// Can uses GroupManager to determines if user have privilege to do something.
func (m *MgoUserManager) Can(user *auth.User, do string) bool {
	for _, pri := range user.Privilege {
		if do == pri {
			return true
		}
	}

	aid := make([]interface{}, 0, len(user.BriefGroups))
	for _, v := range user.BriefGroups {
		aid = append(aid, v.Id)
	}

	groups, err := m.GroupMngr.FindSomeGroup(aid...)
	if err != nil {
		log.Println("mgoauth: cannot find user group to determine privilege - ", err)
		return false
	}

	for _, v := range groups {
		for _, pri := range v.Privilege {
			if do == pri {
				return true
			}
		}
	}

	return false
}

func (m *MgoUserManager) Close() error {
	m.UserColl.Database.Session.Close()
	return nil
}

var _ auth.UserManager = &MgoUserManager{}
