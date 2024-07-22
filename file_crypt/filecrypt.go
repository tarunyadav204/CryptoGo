package filecrypt

import (
	"encoding/hex"
	"io"
	"io/ioutil"

	//"math/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func Encrypt(source string, password []byte) {

	//check source or file exists
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	//Now open the file
	srcFile, err := os.Open(source)
	if err != nil {
		panic(err.Error())
	}

	defer srcFile.Close()

	//Read all plain text from the source File
	plainText, err := ioutil.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}
	key := password
	//Now create a empty nonce of 12byte [0,0,0,0,0,0,0,0,0,0,0,0]
	nonce := make([]byte, 12)

	//now randomize a nonce put random values
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//password based key derviation function = pbkdf.Key()
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha256.New)
	//now Advanced Encryption Algo
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}
	//GCM generates a tag , which is appended to cipher text . This tag is used to verify the integrity of the data upon decryption
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//convert plaintext to cipher text seal function
	cipherText := aesgcm.Seal(nil, nonce, plainText, nil)

	//append nounce to cipherText
	cipherText = append(cipherText, nonce...)

	desFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	defer desFile.Close()
	//write cipherText in desFile created
	_, err = desFile.Write(cipherText)
	if err != nil {
		panic(err.Error())
	}
}

func Decrypt(source string, password []byte) {
	//check source or file exists
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	//Now open the file
	srcFile, err := os.Open(source)
	if err != nil {
		panic(err.Error())
	}
	defer srcFile.Close()

	//Read all plain text from the source File
	cipherText, err := ioutil.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}
	key := password
	salt := cipherText[len(cipherText)-12:] //extract last 12 byte from the cypertext and store in salt

	str := hex.EncodeToString(salt)
	nonce, err := hex.DecodeString(str)
	if err != nil {
		panic(err.Error())
	}

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha256.New)
	//now Advanced Encryption Algo
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}
	//GCM generates a tag , which is appended to cipher text . This tag is used to verify the integrity of the data upon decryption
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, cipherText[:len(cipherText)-12], nil)
	if err != nil {
		panic(err.Error())
	}

	dstFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	defer dstFile.Close()

	_, err = dstFile.Write(plaintext)
	if err != nil {
		panic(err.Error())
	}

}
