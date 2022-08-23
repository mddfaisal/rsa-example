package rsaencryption

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

const (
	PUBLIC_KEY_FILE = "PUBLIC_KEY"
	PRIATE_KEY_FILE = "PRIVATE_KEY"
)

type Rsa struct {
	publicKey  string
	privateKey string
	PlainText  string
	EncText    string
	DecText    string
	Sign       string
	Verify     bool
	bits       int
}

func NewRsaEncryption(plaintext string, enctext string, bits int) *Rsa {
	r := new(Rsa)
	r.PlainText = plaintext
	r.EncText = enctext
	r.bits = bits
	r.setPrivateKey().setPublicKey().generateKeys()
	return r
}

func (r *Rsa) setPublicKey() *Rsa {
	fd, err := os.OpenFile(PUBLIC_KEY_FILE, os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	fd.Close()
	data, err := os.ReadFile(PUBLIC_KEY_FILE)
	if err != nil {
		panic(err)
	}
	r.publicKey = string(data)
	return r
}

func (r *Rsa) setPrivateKey() *Rsa {
	fd, err := os.OpenFile(PRIATE_KEY_FILE, os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	fd.Close()
	data, err := os.ReadFile(PRIATE_KEY_FILE)
	if err != nil {
		panic(err)
	}
	r.privateKey = string(data)
	return r
}

func (r *Rsa) generateKeys() *Rsa {
	if len(r.publicKey) == 0 || len(r.privateKey) == 0 {
		// generate private key
		privKeyBuffer := bytes.NewBuffer(nil)
		privKey, err := rsa.GenerateKey(rand.Reader, r.bits)
		if err != nil {
			panic(err)
		}
		X509PrivKey := x509.MarshalPKCS1PrivateKey(privKey)
		privBlock := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: X509PrivKey,
		}
		pem.Encode(privKeyBuffer, &privBlock)
		r.privateKey = privKeyBuffer.String()
		os.Truncate(PRIATE_KEY_FILE, 0)
		fd, err := os.OpenFile(PRIATE_KEY_FILE, os.O_RDWR, 0644)
		if err != nil {
			panic(err)
		}
		fd.WriteString(r.privateKey)
		fd.Close()

		// generate public key
		pubKeyBuffer := bytes.NewBuffer(nil)
		block, _ := pem.Decode(privKeyBuffer.Bytes())
		if block == nil {
			panic(errors.New("key is invalid format"))
		}
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		publicKey := privateKey.PublicKey
		X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
		if err != nil {
			panic(err)
		}
		publicBlock := pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: X509PublicKey,
		}
		pem.Encode(pubKeyBuffer, &publicBlock)
		r.publicKey = pubKeyBuffer.String()
		os.Truncate(PUBLIC_KEY_FILE, 0)
		fd, err = os.OpenFile(PUBLIC_KEY_FILE, os.O_RDWR, 0644)
		if err != nil {
			panic(err)
		}
		fd.WriteString(r.publicKey)
		fd.Close()
	}
	return r
}

func (r *Rsa) Encrypt() {
	block, _ := pem.Decode([]byte(r.publicKey))
	if block == nil {
		panic(errors.New("key is invalid format"))
	}

	publicKeyParse, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey, ok := publicKeyParse.(*rsa.PublicKey)
	if !ok {
		panic("not a public key type.")
	}
	encBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(r.PlainText))
	if err != nil {
		panic(err)
	}
	r.EncText = string(base64.StdEncoding.EncodeToString(encBytes))
}

func (r *Rsa) Decrypt() {
	block, _ := pem.Decode([]byte(r.privateKey))
	if block == nil {
		panic(errors.New("key is invalid format"))
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	base64DecodedText, err := base64.StdEncoding.DecodeString(r.EncText)
	if err != nil {
		panic(err)
	}
	decBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, base64DecodedText)
	if err != nil {
		panic(err)
	}
	r.DecText = string(decBytes)
}

func (r *Rsa) RSASign() {
	block, _ := pem.Decode([]byte(r.privateKey))
	if block == nil {
		panic(errors.New("key is invalid format"))
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	hash := sha512.New()
	_, err = hash.Write([]byte(r.PlainText))
	if err != nil {
		panic(err)
	}
	bytes := hash.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, bytes)
	if err != nil {
		panic(err)
	}
	r.Sign = string(base64.StdEncoding.EncodeToString(sign))
}

func (r *Rsa) RSAVerify() {
	block, _ := pem.Decode([]byte(r.publicKey))
	if block == nil {
		panic(errors.New("key is invalid format"))
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		panic(errors.New("the kind of key is not a rsa.PublicKey"))
	}
	hash := sha512.New()
	_, err = hash.Write([]byte(r.PlainText))
	if err != nil {
		panic(err)
	}
	bytes := hash.Sum(nil)
	sign, err := base64.StdEncoding.DecodeString(r.Sign)
	if err != nil {
		panic(err)
	}
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, bytes, sign)
	if err == nil {
		r.Verify = true
	}
}
