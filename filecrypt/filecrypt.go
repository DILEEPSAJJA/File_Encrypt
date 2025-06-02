package filecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	//"encoding/binary"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 16
	nonceSize  = 12
	keyLength  = 32
	magicBytes = "FENC" // custom header
)

// EncryptFile encrypts a file using a password and returns the path of the encrypted file
func EncryptFile(inputPath string, password []byte) (string, error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return "", err
	}
	defer input.Close()

	plaintext, err := io.ReadAll(input)
	if err != nil {
		return "", err
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	key := pbkdf2.Key(password, salt, 4096, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	var buffer bytes.Buffer
	buffer.Write([]byte(magicBytes)) // write header
	buffer.Write(salt)
	buffer.Write(nonce)
	buffer.Write(ciphertext)

	outPath := inputPath + ".enc"
	output, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer output.Close()

	_, err = output.Write(buffer.Bytes())
	return outPath, err
}

// DecryptFile decrypts an encrypted file using a password and returns the path of the decrypted file
func DecryptFile(inputPath string, password []byte) (string, error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return "", err
	}
	defer input.Close()

	data, err := io.ReadAll(input)
	if err != nil {
		return "", err
	}

	if len(data) < len(magicBytes)+saltSize+nonceSize {
		return "", errors.New("file too short or corrupted")
	}

	if string(data[:len(magicBytes)]) != magicBytes {
		return "", errors.New("invalid file format")
	}

	salt := data[len(magicBytes) : len(magicBytes)+saltSize]
	nonce := data[len(magicBytes)+saltSize : len(magicBytes)+saltSize+nonceSize]
	ciphertext := data[len(magicBytes)+saltSize+nonceSize:]

	key := pbkdf2.Key(password, salt, 4096, keyLength, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	outPath := inputPath + ".dec"
	output, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer output.Close()

	_, err = output.Write(plaintext)
	return outPath, err
}