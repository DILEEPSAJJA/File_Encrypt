package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/DILEEPSAJJA/File_Encrypt/filecrypt"
)

func main() {
	router := gin.Default()

	router.StaticFile("/", "./static/index.html")

	router.POST("/encrypt", handleEncrypt)
	router.POST("/decrypt", handleDecrypt)

	fmt.Println("Server running on http://localhost:8081")
	router.Static("/static", "./static")
	router.Run(":8081")
}

func handleEncrypt(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "File is required")
		return
	}

	password := c.PostForm("password")
	if len(password) < 4 {
		c.String(http.StatusBadRequest, "Password must be at least 4 characters")
		return
	}

	// Save uploaded file
	tempPath := filepath.Join(os.TempDir(), file.Filename)
	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.String(http.StatusInternalServerError, "Failed to save uploaded file")
		return
	}
	defer os.Remove(tempPath) // clean up temp file

	encPath, err := filecrypt.EncryptFile(tempPath, []byte(password))
	if err != nil {
		c.String(http.StatusInternalServerError, "Encryption failed: %v", err)
		return
	}
	defer os.Remove(encPath) // clean up encrypted file

	c.FileAttachment(encPath, file.Filename+".enc")
}

func handleDecrypt(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "File is required")
		return
	}

	password := c.PostForm("password")
	if len(password) < 4 {
		c.String(http.StatusBadRequest, "Password must be at least 4 characters")
		return
	}

	tempPath := filepath.Join(os.TempDir(), file.Filename)
	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.String(http.StatusInternalServerError, "Failed to save uploaded file")
		return
	}
	defer os.Remove(tempPath)

	decPath, err := filecrypt.DecryptFile(tempPath, []byte(password))
	if err != nil {
		c.String(http.StatusBadRequest, "Decryption failed: %v", err)
		return
	}
	defer os.Remove(decPath)

	originalName := file.Filename[:len(file.Filename)-4] // remove .enc
	c.FileAttachment(decPath, originalName)
}


// package main

// import (
// 	"bytes"
// 	"fmt"
// 	"os"

// 	"github.com/DILEEPSAJJA/File_Encrypt/filecrypt"
// 	"golang.org/x/term"
// )

// func main() {
// 	if len(os.Args) < 2 {
// 		printHelp()
// 		os.Exit(0)
// 	}
// 	function := os.Args[1]

// 	switch function {
// 	case "help":
// 		printHelp()
// 	case "encrypt":
// 		encryptHandle()
// 	case "decrypt":
// 		decryptHandle()
// 	default:
// 		fmt.Println("Run encrypt to encrypt a file or decrypt to decrypt a file.")
// 		os.Exit(1)
// 	}
// }

// func printHelp() {
// 	fmt.Println("file encryption")
// 	fmt.Println("Simple file encrypter for your day-to-day needs.")
// 	fmt.Println()
// 	fmt.Println("Usage:")
// 	fmt.Println("\tgo run . encrypt /path/to/your/file")
// 	fmt.Println()
// 	fmt.Println("Commands:")
// 	fmt.Println("\t encrypt\tEncrypts a file given a password")
// 	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
// 	fmt.Println("\t help\t\tDisplays help text")
// 	fmt.Println()
// }

// func encryptHandle() {
// 	if len(os.Args) < 3 {
// 		fmt.Println("missing the path to the file. For more info, run go run . help")
// 		os.Exit(0)
// 	}
// 	file := os.Args[2]
// 	if !validateFile(file) {
// 		panic("File not found")
// 	}
// 	password := getPassword()
// 	fmt.Println("\nEncrypting...")
// 	filecrypt.Encrypt(file, password)
// 	fmt.Println("\nFile encrypted successfully!")
// }

// func decryptHandle() {
// 	if len(os.Args) < 3 {
// 		fmt.Println("missing the path to the file. For more info, run go run . help")
// 		os.Exit(0)
// 	}
// 	file := os.Args[2]
// 	if !validateFile(file) {
// 		panic("File not found")
// 	}

// 	fmt.Print("Enter password: ")
// 	password, err := term.ReadPassword(int(os.Stdin.Fd()))
// 	if err != nil {
// 		fmt.Println("\nError reading password:", err)
// 		os.Exit(1)
// 	}
// 	fmt.Println("\nDecrypting...")
// 	filecrypt.Decrypt(file, password)
// 	fmt.Println("\nFile successfully decrypted!")
// }

// func getPassword() []byte {
// 	fmt.Print("Enter password: ")
// 	password, err := term.ReadPassword(int(os.Stdin.Fd()))
// 	if err != nil {
// 		fmt.Println("\nError reading password:", err)
// 		os.Exit(1)
// 	}

// 	fmt.Print("\nConfirm password: ")
// 	password2, err := term.ReadPassword(int(os.Stdin.Fd()))
// 	if err != nil {
// 		fmt.Println("\nError reading confirmation:", err)
// 		os.Exit(1)
// 	}

// 	if !validatePassword(password, password2) {
// 		fmt.Println("\nPasswords do not match. Please try again.")
// 		return getPassword()
// 	}
// 	return password
// }

// func validatePassword(password1 []byte, password2 []byte) bool {
// 	return bytes.Equal(password1, password2)
// }

// func validateFile(file string) bool {
// 	_, err := os.Stat(file)
// 	return !os.IsNotExist(err)
// }