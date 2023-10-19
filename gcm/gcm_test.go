package gcm_test

import (
	"bytes"
	"encoding/base64"
	"github.com/xorta-std/golang-playground/gcm"
	"path"
	"testing"
)

//const saltStr = "jp9X5s0VGMor9NKiB4GmTg=="
//const ivStr = "AemKsxmeJ4cjmkrw"

var saltStr, _ = gcm.NewSalt()
var ivStr, _ = gcm.NewIV()

var key, _ = gcm.DeriveKeyFromPassword("password", saltStr, 14686)
var iv, _ = base64.StdEncoding.DecodeString(ivStr)

func isEncrypted(encryptedData, plainData []byte) bool {
	if len(encryptedData) <= len(plainData) {
		return false
	}
	if len(plainData) > 0 {
		if bytes.Contains(encryptedData, plainData) {
			return false
		}
	}
	return true
}

func TestEncryption(t *testing.T) {
	const plainText = "Hello, world!"
	encryptedText, err := gcm.Encrypt([]byte(plainText), key, iv)
	if err != nil {
		t.Fatalf("Encryption failed with error: %v", err)
	}
	if !isEncrypted(encryptedText, []byte(plainText)) {
		t.Errorf("Encryption failed: Data is not encrypted!")
	}

	plainText2, err := gcm.Decrypt(encryptedText, key, iv)
	if err != nil {
		t.Fatalf("Decryption failed with error: %v", err)
	}

	if plainText != string(plainText2) {
		t.Fatalf("Encryption -> decryption failed: Expected '%s', but got '%s'", plainText, plainText2)
	}
}

func TestFileEncryption(t *testing.T) {
	const prefix = "./assets"

	const filename = "top-secret-message.txt"
	const encryptedFilename = filename + ".encrypted"
	const decryptedFilename = "decrypted." + filename

	path.Join()
	err := gcm.EncryptFile(path.Join(prefix, filename), path.Join(prefix, encryptedFilename), key, iv)
	if err != nil {
		t.Fatal(err)
	}

	err = gcm.DecryptFile(path.Join(prefix, encryptedFilename), path.Join(prefix, decryptedFilename), key, iv)
	if err != nil {
		t.Fatal(err)
	}
}
