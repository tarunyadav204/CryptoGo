# CryptoGo

🔐 **CryptoGo**: A Simple File Encryption Tool Built with Go!

## Features:
1. **File Encryption**: Easily encrypt files with a secure password to keep your data safe.
2. **File Decryption**: Decrypt files using the password to access your data.
3. **Secure Password Handling**: Passwords are read securely from the terminal to ensure confidentiality.
4. **Robust Encryption Algorithm**: Utilizes PBKDF2 for key derivation and AES-GCM for encryption.

## How It Works:

### Encrypting a File:
1. Run the command: `CryptoGo encrypt /path/to/your/file`.
2. Enter and confirm your password securely in the terminal.
3. Your file is now encrypted and protected!

### Decrypting a File:
1. Run the command: `CryptoGo decrypt /path/to/your/file`.
2. Enter your password securely in the terminal.
3. Your file is decrypted and accessible!

## Technical Details:
- **Programming Language**: Go (Golang)
- **Encryption Algorithm**: AES-GCM with a 256-bit key derived using PBKDF2.
- **Password Handling**: Secure terminal password input using `golang.org/x/term`.

## Usage Example:
```go
func Encrypt(source string, password []byte) {
    srcFile, err := os.Open(source)
    if err != nil {
        panic(err.Error())
    }
    defer srcFile.Close()

    plainText, err := ioutil.ReadAll(srcFile)
    if err != nil {
        panic(err.Error())
    }

    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        panic(err.Error())
    }

    dk := pbkdf2.Key(password, nonce, 4096, 32, sha256.New)
    block, err := aes.NewCipher(dk)
    if err != nil {
        panic(err.Error())
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(err.Error())
    }

    cipherText := aesgcm.Seal(nil, nonce, plainText, nil)
    cipherText = append(cipherText, nonce...)

    desFile, err := os.Create(source)
    if err != nil {
        panic(err.Error())
    }
    defer desFile.Close()

    _, err = desFile.Write(cipherText)
    if err != nil {
        panic(err.Error())
    }
}
