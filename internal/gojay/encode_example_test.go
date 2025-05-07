package gojay_test

import (
	"fmt"
	"log"
	"os"

	"github.com/francoispqt/gojay"
)

func ExampleMarshal_string() {
	str := "gojay"
	d, err := gojay.Marshal(str)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(d)) // "gojay"
}

func ExampleMarshal_bool() {
	b := true
	d, err := gojay.Marshal(b)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(d)) // true
}

func ExampleNewEncoder() {
	enc := gojay.BorrowEncoder(os.Stdout)

	var str = "gojay"
	err := enc.EncodeString(str)
	if err != nil {
		log.Fatal(err)
	}
	// Output:
	// "gojay"
}

func ExampleBorrowEncoder() {
	enc := gojay.BorrowEncoder(os.Stdout)
	defer enc.Release()

	var str = "gojay"
	err := enc.EncodeString(str)
	if err != nil {
		log.Fatal(err)
	}
	// Output:
	// "gojay"
}

func ExampleEncoder_EncodeString() {
	enc := gojay.BorrowEncoder(os.Stdout)
	defer enc.Release()

	var str = "gojay"
	err := enc.EncodeString(str)
	if err != nil {
		log.Fatal(err)
	}
	// Output:
	// "gojay"
}
