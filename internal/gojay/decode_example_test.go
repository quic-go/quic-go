package gojay_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/francoispqt/gojay"
)

func ExampleUnmarshal_string() {
	data := []byte(`"gojay"`)
	var str string
	err := gojay.Unmarshal(data, &str)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(str) // true
}

func ExampleUnmarshal_bool() {
	data := []byte(`true`)
	var b bool
	err := gojay.Unmarshal(data, &b)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(b) // true
}

func ExampleUnmarshal_invalidType() {
	data := []byte(`"gojay"`)
	someStruct := struct{}{}
	err := gojay.Unmarshal(data, &someStruct)

	fmt.Println(err) // "Cannot unmarshal JSON to type '*struct{}'"
}

func ExampleDecoder_Decode_string() {
	var str string
	dec := gojay.BorrowDecoder(strings.NewReader(`"gojay"`))
	err := dec.Decode(&str)
	dec.Release()

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(str) // "gojay"
}

func ExampleDecodeObjectFunc() {
	reader := strings.NewReader(`{
		"name": "John Doe",
		"email": "john.doe@email.com" 
	}`)
	dec := gojay.NewDecoder(reader)

	user := struct {
		name  string
		email string
	}{}
	dec.DecodeObject(gojay.DecodeObjectFunc(func(dec *gojay.Decoder, k string) error {
		switch k {
		case "name":
			return dec.String(&user.name)
		case "email":
			return dec.String(&user.email)
		}
		return nil
	}))

	fmt.Printf("User\nname: %s\nemail: %s", user.name, user.email)

	// Output:
	// User
	// name: John Doe
	// email: john.doe@email.com
}

func ExampleDecodeArrayFunc() {
	reader := strings.NewReader(`[
		"foo",
		"bar"
	]`)
	dec := gojay.NewDecoder(reader)

	strSlice := make([]string, 0)
	err := dec.DecodeArray(gojay.DecodeArrayFunc(func(dec *gojay.Decoder) error {
		var str string
		if err := dec.AddString(&str); err != nil {
			return err
		}
		strSlice = append(strSlice, str)
		return nil
	}))

	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(strSlice)
	// Output:
	// [foo bar]
}

func ExampleNewDecoder() {
	reader := strings.NewReader(`"gojay"`)
	dec := gojay.NewDecoder(reader)

	var str string
	err := dec.DecodeString(&str)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(str)
	// Output:
	// gojay
}

func ExampleBorrowDecoder() {
	reader := strings.NewReader(`"gojay"`)
	dec := gojay.BorrowDecoder(reader)
	defer dec.Release()

	var str string
	err := dec.DecodeString(&str)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(str)
	// Output:
	// gojay
}

func ExampleDecoder_DecodeBool() {
	reader := strings.NewReader(`true`)
	dec := gojay.NewDecoder(reader)

	var b bool
	err := dec.DecodeBool(&b)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(b)
	// Output:
	// true
}
