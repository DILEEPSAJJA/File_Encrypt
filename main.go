package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/DILEEPSAJJA/File_Encrypt/filecrypt"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}
	function := os.Args[1]

	switch function {
	case "help":
		printHelp()
	case "encrypt":
		encryptHandle()
	case "decrypt":
		decryptHandle()
	default:
		fmt.Println("Run encrypt to encrypt a file or decrypt to decrypt a file.")
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("file encryption")
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("\tgo run . encrypt /path/to/your/file")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println()
}

func encryptHandle() {
	if len(os.Args) < 3 {
		fmt.Println("missing the path to the file. For more info, run go run . help")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		panic("File not found")
	}
	password := getPassword()
	fmt.Println("\nEncrypting...")
	filecrypt.Encrypt(file, password)
	fmt.Println("\nFile encrypted successfully!")
}

func decryptHandle() {
	if len(os.Args) < 3 {
		fmt.Println("missing the path to the file. For more info, run go run . help")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		panic("File not found")
	}

	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	fmt.Println("\nDecrypting...")
	filecrypt.Decrypt(file, password)
	fmt.Println("\nFile successfully decrypted!")
}

func getPassword() []byte {
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}

	fmt.Print("\nConfirm password: ")
	password2, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\nError reading confirmation:", err)
		os.Exit(1)
	}

	if !validatePassword(password, password2) {
		fmt.Println("\nPasswords do not match. Please try again.")
		return getPassword()
	}
	return password
}

func validatePassword(password1 []byte, password2 []byte) bool {
	return bytes.Equal(password1, password2)
}

func validateFile(file string) bool {
	_, err := os.Stat(file)
	return !os.IsNotExist(err)
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
// 	fmt.Println("")
// 	fmt.Println("Usage:")
// 	fmt.Println("")
// 	fmt.Println("\tgo run . encrypt /path/to/your/file")
// 	fmt.Println("")
// 	fmt.Println("Commands:")
// 	fmt.Println("")
// 	fmt.Println("\t encrypt\tEncrypts a file given a password")
// 	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
// 	fmt.Println("\t help\t\tDisplays help text")
// 	fmt.Println("")
// }

// func encryptHandle() {
// 	if len(os.Args) < 3 {
// 		fmt.Println("missing the path to the file. For more info, run go run. help")
// 		os.Exit(0)
// 	}
// 	file := os.Args[2]
// 	if !validateFile(file) {
// 		panic("File not found")
// 	}
// 	password := getPassword()
// 	fmt.Println("\nEncrypting...")
// 	filecrypt.Encrypt(file, password)
// 	fmt.Println("\n file encrypted successfully!")
// }

// func decryptHandle() {
// 	if len(os.Args) < 3 {
// 		fmt.Println("missing the path to the file. For more info, run go run. help")
// 		os.Exit(0)
// 	}
// 	file := os.Args[2]
// 	if !validateFile(file) {
// 		panic("File not found")
// 	}
// 	fmt.Print("Enter password: ") // previously had no colon
// 	password, _ := term.ReadPassword(0)

// 	fmt.Println("\nDecrypting...")
// 	filecrypt.Decrypt(file, password)
// 	fmt.Println("\n file sucessfully decrypted")
// }

// func getPassword() []byte {
// 	fmt.Print("Enter password: ")
// 	fmt.Println(" [waiting for input...]") // DEBUG

// 	password, err := term.ReadPassword(0)
// 	if err != nil {
// 		fmt.Println("Error reading password:", err)
// 		os.Exit(1)
// 	}

// 	fmt.Println("\nConfirm password: ")
// 	password2, err := term.ReadPassword(0)
// 	if err != nil {
// 		fmt.Println("Error reading confirmation:", err)
// 		os.Exit(1)
// 	}

// 	if !validatePassword(password, password2) {
// 		fmt.Println("\nPasswords do not match. Please try again.")
// 		return getPassword()
// 	}
// 	return password
// }

// // func getPassword() []byte {
// // 	fmt.Print("Enter password: ") // <-- added space and colon
// // 	password, _ := term.ReadPassword(0)

// // 	fmt.Print("\nConfirm password: ") // <-- fixed spelling + newline
// // 	password2, _ := term.ReadPassword(0)

// // 	if !validatePassword(password, password2) {
// // 		fmt.Print("\nPasswords do not match. Please try again.\n")
// // 		return getPassword()
// // 	}
// // 	return password
// // }

// func validatePassword(password1 []byte, password2 []byte) bool {
// 	if !bytes.Equal(password1, password2) {
// 		return false
// 	}
// 	return true
// }

// // func validatePassword(pw1, pw2 []byte) bool {
// // 	return bytes.Equal(pw1, pw2)
// // }

// func validateFile(file string) bool {
// 	if _, err := os.Stat(file); os.IsNotExist(err) {
// 		return false
// 	}
// 	return true
// }
