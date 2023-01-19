package main

import (
	"fmt"
	"rsa-example/rsaencryption"
)

func main() {
	// encryption
	msg := `{"hello": "world"}`
	r := rsaencryption.NewRsaEncryption(msg, "", 2048)
	r.Encrypt()
	fmt.Println("plain text: ", msg)
	fmt.Println("encrypted text: ", r.EncText)

	// decryption
	r.Decrypt()
	fmt.Println("decrypted text: ", r.DecText)

	// sign and verify
	r.RSASign()
	fmt.Println("sign: ", r.Sign)
	r.RSAVerify()
	fmt.Println("verify: ", r.Verify)
}
