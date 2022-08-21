package main

import (
	"fmt"
	"rsa-example/rsaencryption"
)

func main() {
	// encryption
	msg := "helloworld"
	r := rsaencryption.NewRsaEncryption(msg, "", 2048)
	r.Encrypt()
	fmt.Println("plain text: ", msg)
	fmt.Println("encrypted text: ", r.EncText)

	r.Decrypt()
	fmt.Println("decrypted text: ", r.DecText)
}
