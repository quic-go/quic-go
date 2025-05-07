package gojay_test

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/francoispqt/gojay"
)

type User struct {
	ID    int
	Name  string
	Email string
}

func (u *User) UnmarshalJSONObject(dec *gojay.Decoder, k string) error {
	switch k {
	case "id":
		return dec.Int(&u.ID)
	case "name":
		return dec.String(&u.Name)
	case "email":
		return dec.String(&u.Email)
	}
	return nil
}

func (u *User) NKeys() int {
	return 3
}

func (u *User) MarshalJSONObject(enc *gojay.Encoder) {
	enc.IntKey("id", u.ID)
	enc.StringKey("name", u.Name)
	enc.StringKey("email", u.Email)
}

func (u *User) IsNil() bool {
	return u == nil
}

func Example_decodeEncode() {
	reader := strings.NewReader(`{
		"id": 1,
		"name": "John Doe",
		"email": "john.doe@email.com"
	}`)
	dec := gojay.BorrowDecoder(reader)
	defer dec.Release()

	u := &User{}
	err := dec.Decode(u)
	if err != nil {
		log.Fatal(err)
	}

	enc := gojay.BorrowEncoder(os.Stdout)
	err = enc.Encode(u)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\nUser ID: %d\nName: %s\nEmail: %s\n",
		u.ID, u.Name, u.Email)

	// Output:
	// {"id":1,"name":"John Doe","email":"john.doe@email.com"}
	// User ID: 1
	// Name: John Doe
	// Email: john.doe@email.com
}
