package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

var (
	invalidKeyErr error
)

func init() {
	invalidKeyErr = errors.New("invalid key")
}

func dirIsExist(dir string) bool {
	_, err := os.Stat(dir)
	if err == nil {
		return true
	}
	return os.IsExist(err)
}

func GenRSAKey(outputDir string, bits int) error {
	var err error
	defer func() {
		if err != nil {
			fmt.Println("Generate Key failed")
		} else {
			fmt.Println("Generate Key success")
		}
	}()
	privatePath := outputDir + "/private.pem"
	publicPath := outputDir + "/public.pem"
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	//save private key
	private := x509.MarshalPKCS1PrivateKey(key)
	block := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: private,
	}
	if !dirIsExist(outputDir) {
		os.Mkdir(outputDir, os.ModePerm)
	}
	file, err := os.Create(privatePath)
	if err != nil {
		return err
	}
	err = pem.Encode(file, &block)
	if err != nil {
		return err
	}

	//save public key
	public := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	block = pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: public,
	}
	file, err = os.Create(publicPath)
	if err != nil {
		return err
	}
	err = pem.Encode(file, &block)
	if err != nil {
		return err
	}
	return nil
}

func SignByRSA(keyPath string, message string) (res string, err error) {
	defer func() {
		if err != nil {
			fmt.Println("Sign message by rsa failed")
		} else {
			fmt.Println("Sign message by rsa success")
		}
	}()
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return
	}
	block, _ := pem.Decode(key)
	if block == nil {
		err = invalidKeyErr
		return
	}
	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	fmt.Printf("message is %v\n", message)
	h := sha256.New()
	h.Write([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return
	}
	res = base64.StdEncoding.EncodeToString(signature)
	return
}

func VerifySignature(keyPath, signature, message string) (success bool, err error) {
	defer func() {
		if err != nil {
			fmt.Println("Verify signature failed")
		} else {
			fmt.Println("Verify signature success")
		}
	}()
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return
	}
	block, _ := pem.Decode(key)
	if block == nil {
		err = invalidKeyErr
		return
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return
	}
	token, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return
	}
	fmt.Printf("message is %v\n", message)
	h := sha256.New()
	h.Write([]byte(message))
	isValid := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h.Sum(nil), token)
	if isValid == nil {
		success = true
	}
	return
}
