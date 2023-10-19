package gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"os"
)

func DeriveKeyFromPassword(password string, saltBase64 string, iterations int) ([]byte, error) {
	keyMaterial := []byte(password)
	salt, err := base64.StdEncoding.DecodeString(saltBase64)
	if err != nil {
		return nil, err
	}
	key := pbkdf2.Key(keyMaterial, salt, iterations, 32, sha256.New)
	return key, nil
}

func Decrypt(inputBuffer, key, IV []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, IV, inputBuffer, nil)
	return plaintext, err
}

func Encrypt(inputBuffer, key, IV []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext := aesgcm.Seal(nil, IV, inputBuffer, nil)
	return plaintext, err
}

func DecryptFile(fIn, fOut string, key, iv []byte) error {
	inputFile, _ := os.ReadFile(fIn)
	output, err := Decrypt(inputFile, key, iv)
	if err != nil {
		return err
	}
	err = os.WriteFile(fOut, output, 0666)
	if err != nil {
		return err
	}
	return nil
}

func EncryptFile(fIn, fOut string, key, iv []byte) error {
	inputFile, _ := os.ReadFile(fIn)
	output, err := Encrypt(inputFile, key, iv)
	if err != nil {
		return err
	}
	err = os.WriteFile(fOut, output, 0666)
	if err != nil {
		return err
	}
	return nil
}

func RandomBytes(l int) ([]byte, error) {
	randomBytes := make([]byte, l)
	_, err := rand.Read(randomBytes)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
		return nil, err
	}
	return randomBytes, nil
}

func RandomB64Bytes(l int) (string, error) {
	b, err := RandomBytes(l)
	if err != nil {
		return "", err
	}
	s := base64.StdEncoding.EncodeToString(b)
	return s, nil
}

func NewSalt() (string, error) {
	return RandomB64Bytes(16)
}

func NewIV() (string, error) {
	return RandomB64Bytes(12)
}
