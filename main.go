package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/dgrijalva/jwt-go"
)

var jwtPublicKey *rsa.PublicKey
var jwtPrivateKey *rsa.PrivateKey

const jwtPublic = "public.pem"
const jwtPrivate = "private.pem"

func initKeys() {
	file, err := os.Open(jwtPublic)
	if err != nil {
		log.Fatal(err)
	}

	jwtPublicBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("My public key: ", string(jwtPublicBytes))

	file.Close()

	enc := base64.StdEncoding.EncodeToString(jwtPublicBytes)
	fmt.Println(enc)

	pubKey := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEMWF0YzEzOUlBYjRycHcycWxBUmRxbnphbgpFZFF0dlpkYnFVclB3Z0ZteWxHSnpSYURtbHMyb1NyN1lxTWxhWDJiYnZTd1B5WnRGODhsNHg2cFhjSk0xUGpHCm1VOW9weStGbklKMmFKajVwdi9SME1kSHJzNVpIbDJvT3ZwcG5TSE1MdCtON3FRbFVld1RXZ25WemY0SEhjaFUKM2ZHYVBCYmFHdC9SaSszTmpRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="

	jwtPublicBytes, _ = base64.StdEncoding.DecodeString(pubKey)

	jwtPublicKey, err = jwt.ParseRSAPublicKeyFromPEM(jwtPublicBytes)
	if err != nil {
		log.Fatal(err)
	}

	file, err = os.Open(jwtPrivate)
	if err != nil {
		log.Fatal(err)
	}

	jwtPrivateBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	file.Close()

	jwtPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(jwtPrivateBytes)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	initKeys()

	lexaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	lexaPublicKey := &lexaPrivateKey.PublicKey

	var pemPrivateBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(lexaPrivateKey),
	}

	var b bytes.Buffer

	err = pem.Encode(&b, pemPrivateBlock)

	fmt.Println("Lexa Private Key: ", base64.StdEncoding.EncodeToString(b.Bytes()))

	message := []byte(`{ "role": "admin" }`)
	hash := sha256.New()
	label := []byte("")

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, lexaPublicKey, message, label)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Encrypted: %x\n", ciphertext)

	ciphermsg := fmt.Sprintf("%x", ciphertext)

	var opts rsa.PSSOptions
	opts.SaltLength = 10
	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, jwtPrivateKey, newhash, hashed, &opts)

	if err != nil {
		panic(err)
	}

	fmt.Println(signature)

	fmt.Printf("PSS Signature: %x\n", signature)

	sign := fmt.Sprintf("%x", signature)

	b64sign := base64.StdEncoding.EncodeToString(signature)

	fmt.Println("b64sign: ", b64sign)

	res, _ := base64.StdEncoding.DecodeString(b64sign)

	fmt.Println("Res: ", res)

	newSignature := make([]byte, hex.DecodedLen(len([]byte(sign))))

	_, err = hex.Decode(newSignature, []byte(sign))

	fmt.Println(newSignature)

	newCipherMsg := make([]byte, hex.DecodedLen(len([]byte(ciphermsg))))

	_, err = hex.Decode(newCipherMsg, []byte(ciphermsg))

	plainText, err := rsa.DecryptOAEP(newhash.New(), rand.Reader, lexaPrivateKey, newCipherMsg, []byte(""))
	if err != nil {
		panic(err)
	}

	fmt.Println("Decoded: ", string(plainText))

	err = rsa.VerifyPSS(jwtPublicKey, newhash, hashed, newSignature, &opts)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("Verify Signature successfull")
	}

}
