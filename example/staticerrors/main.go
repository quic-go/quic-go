package main

import "fmt"

type user struct {
	name string
	age  int
}

func main() {
	fmt.Println(getHello())

	u := &user{name: "John Doe"}
	fmt.Println(u)
}

func getHello() string {
	return fmt.Sprintf("Hallo")
}
