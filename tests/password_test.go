package bcrypt_test

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/gopsql/bcrypt"
	"github.com/gopsql/gopg"
	"github.com/gopsql/logger"
	"github.com/gopsql/pq"
	"github.com/gopsql/psql"
)

type (
	user struct {
		Id       int
		Password myPassword
	}

	myPassword struct {
		bcrypt.HashedPassword
		Password string
	}

	admin struct {
		Id            int
		Password      bcrypt.Password
		OtherPassword *bcrypt.Password
	}

	userInGOPG struct {
		__TABLE_NAME__ string `users`

		Id       int
		Password myPasswordInGOPG
	}

	myPasswordInGOPG struct {
		myPassword
	}
)

func (p myPassword) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Password)
}

func (p *myPassword) UnmarshalJSON(t []byte) error {
	var value string
	if err := json.Unmarshal(t, &value); err != nil {
		return err
	}
	*p = myPassword{}
	p.Password = value
	return p.Update(value)
}

func (p *myPasswordInGOPG) ScanValue(rd gopg.TypesReader, n int) error { // go-pg
	value, err := gopg.TypesScanString(rd, n)
	if err == nil {
		*p = myPasswordInGOPG{}
		p.HashedPassword.Hashed = value
	}
	return err
}

func TestPassword(_t *testing.T) {
	t := test{_t, 0}

	u := user{}
	t.String(u.Password.Password, "")
	t.String(u.Password.Hashed, "")
	t.False(u.Password.Equal("foobar"))
	u.Password.Password = "foobar"
	u.Password.MustUpdate("foobar")
	t.String(u.Password.Password, "foobar")
	t.Int(len(u.Password.Hashed), 60)
	t.True(u.Password.Equal("foobar"))

	u2 := user{}
	t.Int(len(u2.Password.Hashed), 0)
	t.False(u2.Password.Equal("fortest"))
	mustUnmarshal(`{"Password":"fortest"}`, &u2)
	t.Int(len(u2.Password.Hashed), 60)
	t.True(u2.Password.Equal("fortest"))

	a := admin{}
	t.String(a.Password.Password, "")
	t.String(a.Password.Hashed, "")
	t.False(a.Password.Equal("hello"))
	a.Password.MustUpdate("hello")
	t.String(a.Password.Password, "hello")
	t.Int(len(a.Password.Hashed), 60)
	t.True(a.Password.Equal("hello"))

	a2 := admin{}
	t.Int(len(a2.Password.Hashed), 0)
	t.False(a2.Password.Equal("world"))
	mustUnmarshal(`{"Password":"world"}`, &a2)
	t.Int(len(a2.Password.Hashed), 60)
	t.True(a2.Password.Equal("world"))
}

func TestInDatabase(_t *testing.T) {
	t := test{_t, 0}

	connStr := os.Getenv("DBCONNSTR")
	if connStr == "" {
		connStr = "postgres://localhost:5432/gopsql?sslmode=disable"
	}

	conn := pq.MustOpen(connStr)
	u := psql.NewModel(user{}, conn, logger.StandardLogger)

	u.NewSQL(u.DropSchema()).MustExecute()
	u.NewSQL(u.Schema()).MustExecute()

	var newUserId int
	u.Insert(u.Permit("Password").Filter(`{"Password":""}`)).Returning("id").MustQueryRow(&newUserId)
	var u1 user
	u.Find("WHERE id = $1", newUserId).MustQuery(&u1)
	t.String(u1.Password.Hashed, "") // empty password should have empty hash
	t.False(u1.Password.Equal(""))   // empty password should never pass

	u.Update(u.Permit("Password").Filter(`{"Password":"newpass"}`)).Where("id = $1", newUserId).MustExecute()
	var u2 user
	u.Find("WHERE id = $1", newUserId).MustQuery(&u2)
	t.Int(len(u2.Password.Hashed), 60)
	t.True(u2.Password.Equal("newpass"))

	a := psql.NewModel(admin{})
	a.SetConnection(conn)
	a.SetLogger(logger.StandardLogger)

	a.NewSQL(a.DropSchema()).MustExecute()
	a.NewSQL(a.Schema()).MustExecute()

	var newAdminId int
	a.Insert(
		a.Permit("Password", "OtherPassword").
			Filter(`{"Password":"admin","OtherPassword":"random"}`),
	).Returning("id").MustQueryRow(&newAdminId)
	var a1 admin
	a1.Password.MustUpdate("foo")
	a1.OtherPassword = &bcrypt.Password{}
	a1.OtherPassword.MustUpdate("bar")
	a.Find("WHERE id = $1", newAdminId).MustQuery(&a1)
	t.String(a1.Password.Password, "")
	t.Int(len(a1.Password.Hashed), 60)
	t.True(a1.Password.Equal("admin"))
	t.String(a1.OtherPassword.Password, "")
	t.Int(len(a1.OtherPassword.Hashed), 60)
	t.True(a1.OtherPassword.Equal("random"))

	conn.Close()

	log.Println("testing in gopg")

	conn2 := gopg.MustOpen(connStr)
	u.SetConnection(conn2)

	var u3 user
	u.Find("WHERE id = $1", newUserId).MustQuery(&u3)
	t.String(u3.Password.Hashed, "") // because ScanValue is not defined

	var u4 userInGOPG
	u = psql.NewModel(userInGOPG{}, conn2, logger.StandardLogger)
	u.Find("WHERE id = $1", newUserId).MustQuery(&u4)
	t.Int(len(u4.Password.Hashed), 60)
	t.True(u4.Password.Equal("newpass"))

	conn2.Close()
}

func mustUnmarshal(in string, out interface{}) {
	if err := json.Unmarshal([]byte(in), out); err != nil {
		panic(err)
	}
}

type (
	test struct {
		*testing.T
		i int
	}
)

func (t *test) String(got, expected string) {
	t.Helper()
	if got == expected {
		t.Logf("case %d passed", t.i)
	} else {
		t.Errorf("case %d failed, got %s", t.i, got)
	}
	t.i++
}

func (t *test) Int(got, expected int) {
	t.Helper()
	if got == expected {
		t.Logf("case %d passed", t.i)
	} else {
		t.Errorf("case %d failed, got %d", t.i, got)
	}
	t.i++
}

func (t *test) True(got bool) {
	t.Helper()
	if got == true {
		t.Logf("case %d passed", t.i)
	} else {
		t.Errorf("case %d failed, got false", t.i)
	}
	t.i++
}

func (t *test) False(got bool) {
	t.Helper()
	if got == false {
		t.Logf("case %d passed", t.i)
	} else {
		t.Errorf("case %d failed, got true", t.i)
	}
	t.i++
}
