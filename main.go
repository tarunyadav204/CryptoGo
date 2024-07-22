package main

import (
	"bytes"
	"fmt"
	filecrypt "go-file-encryption/file_crypt"
	"os"
	"syscall"

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
		encryptHandler()

	case "decrypt":
		decryptHandler()

	default:
		fmt.Println("Run encrypt to encrypt a file, and decrypt to decrypt a file")

		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("CryptoGo")
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tCryptoGo encrypt /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")
}

func encryptHandler() {

	if len(os.Args) < 3 {
		fmt.Println("Missing the path to the file. For more information run CryptoGo help")
		os.Exit(0)
	}

	file := os.Args[2]

	if !validateFile(file) {
		//fmt.Println()
		panic("File not found")

	}

	password := getPassword()
	fmt.Println("Encrypting..........")
	//fmt.Println("password......", password)
	filecrypt.Encrypt(file, password)
	fmt.Println("File successfully protected")

}

func decryptHandler() {
	if len(os.Args) < 3 {
		fmt.Println("Missing the path to the file. For more information run CryptoGo help")
		os.Exit(0)
	}

	file := os.Args[2]

	if !validateFile(file) {
		//fmt.Println()
		panic("File not found")

	}
	fmt.Println("Enter password: ")
	password, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println("Decrypting.........")
	filecrypt.Decrypt(file, password)
	fmt.Println("File Successfully decrypted")
}

func getPassword() []byte {

	fmt.Print("Enter password: ")
	//password, _ := terminal.ReadPassword(0)
	password, _ := term.ReadPassword(int(syscall.Stdin))

	fmt.Print("\nConfirm password: ")
	//password2, _ := terminal.ReadPassword(0)
	password2, _ := term.ReadPassword(int(syscall.Stdin))

	if !validatePassword(password, password2) {
		fmt.Print("\nPasswords do not match. Please try again.\n")
		return getPassword()
	}
	return password
}

func validatePassword(password1 []byte, password2 []byte) bool {
	/* if !bytes.Equal(password1,password2){
	       return false
	   }
	   return true*/
	return bytes.Equal(password1, password2)
}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}

	return true
}
