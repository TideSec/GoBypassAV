package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	// X Packages
	"golang.org/x/crypto/argon2"
)

func main() {
	verbose := flag.Bool("v", false, "Enable verbose output")
	encryptionType := flag.String("type", "", "The type of encryption to use [xor, aes256, rc4, null]")
	key := flag.String("key", "", "Encryption key")
	b64 := flag.Bool("base64", false, "Base64 encode the output. Can be used with or without encryption")
	input := flag.String("i", "", "Input file path of binary file")
	output := flag.String("o", "", "Output file path")
	mode := flag.String("mode", "encrypt", "Mode of operation to perform on the input file [encrypt,decrypt]")
	salt := flag.String("salt", "", "Salt, in hex, used to generate an AES256 32-byte key through Argon2. Only used during decryption")
	inputNonce := flag.String("nonce", "", "Nonce, in hex, used to decrypt an AES256 input file. Only used during decryption")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	// Check to make sure the input file exists
	_, errInputFile := os.Stat(*input)

	if os.IsNotExist(errInputFile) {
		os.Exit(1)
	}

	shellcode, errShellcode := ioutil.ReadFile(*input)

	if errShellcode != nil {
		os.Exit(1)
	}

	// Check to make sure an output file was provided
	if *output == "" {
		os.Exit(1)
	}

	// Check to make sure the output directory exists
	dir, _ := filepath.Split(*output)
	if *verbose {
	}

	outDir, errOutDir := os.Stat(dir)
	if errOutDir != nil {
		os.Exit(1)
	}

	if !outDir.IsDir() {
	}

	if *verbose {
	}

	if strings.ToUpper(*mode) != "ENCRYPT" && strings.ToUpper(*mode) != "DECRYPT" {
		os.Exit(1)
	}

	// Make sure a key was provided
	if *encryptionType != "" {
		if *key == "" {
			os.Exit(1)
		}
	}

	var outputBytes []byte

	switch strings.ToUpper(*mode) {
	case "ENCRYPT":
		var encryptedBytes []byte
		switch strings.ToUpper(*encryptionType) {
		case "XOR":
			// https://kylewbanks.com/blog/xor-encryption-using-go
			if *verbose {
			}
			encryptedBytes = make([]byte, len(shellcode))
			tempKey := *key
			for k, v := range shellcode {
				encryptedBytes[k] = v ^ tempKey[k%len(tempKey)]
			}
		case "AES256":
			// https://github.com/gtank/cryptopasta/blob/master/encrypt.go
			if *verbose {
			}

			// Generate a salt that is used to generate a 32 byte key with Argon2
			salt := make([]byte, 32)
			_, errReadFull := io.ReadFull(rand.Reader, salt)
			if errReadFull != nil {
				os.Exit(1)
			}

			// Generate Argon2 ID key from input password using a randomly generated salt
			aesKey := argon2.IDKey([]byte(*key), salt, 1, 64*1024, 4, 32)
			// I leave it up to the operator to use the password + salt for decryption or just the Argon2 key

			// Generate AES Cipher Block
			cipherBlock, err := aes.NewCipher(aesKey)
			if err != nil {
			}
			gcm, _ := cipher.NewGCM(cipherBlock)
			if err != nil {
				os.Exit(1)
			}

			// Generate a nonce (or IV) for use with the AES256 function
			nonce := make([]byte, gcm.NonceSize())
			_, errNonce := io.ReadFull(rand.Reader, nonce)
			if errNonce != nil {
				os.Exit(1)
			}


			encryptedBytes = gcm.Seal(nil, nonce, shellcode, nil)
		case "RC4":
			if *verbose {
			}
			cipher, err := rc4.NewCipher([]byte(*key))
			if err != nil {
				os.Exit(1)
			}
			encryptedBytes = make([]byte, len(shellcode))
			cipher.XORKeyStream(encryptedBytes, shellcode)
		case "":
			if *verbose {
			}
			encryptedBytes = append(encryptedBytes, shellcode...)
		default:
			os.Exit(1)
		}

		if len(encryptedBytes) <= 0 {
			os.Exit(1)
		}
		if *b64 {
			outputBytes = make([]byte, base64.StdEncoding.EncodedLen(len(encryptedBytes)))
			base64.StdEncoding.Encode(outputBytes, encryptedBytes)
		} else {
			outputBytes = append(outputBytes, encryptedBytes...)
		}
	case "DECRYPT":
		var decryptedBytes []byte
		switch strings.ToUpper(*encryptionType) {
		case "AES256":
			// https://github.com/gtank/cryptopasta/blob/master/encrypt.go
			if *verbose {
			}
			// I leave it up to the operator to use the password + salt for decryption or just the Argon2 key
			if *salt == "" {
				os.Exit(1)
			}
			if len(*salt) != 64 {
				os.Exit(1)
			}

			saltDecoded, _ := hex.DecodeString(*salt)
			if errShellcode != nil {
				os.Exit(1)
			}
			if *verbose {
			}

			aesKey := argon2.IDKey([]byte(*key), saltDecoded, 1, 64*1024, 4, 32)
			if *verbose {
			}

			cipherBlock, err := aes.NewCipher(aesKey)
			if err != nil {
			}

			gcm, _ := cipher.NewGCM(cipherBlock)
			if err != nil {
				os.Exit(1)
			}

			if len(shellcode) < gcm.NonceSize() {
				os.Exit(1)
			}

			if len(*inputNonce) != gcm.NonceSize()*2 {
				os.Exit(1)
			}
			decryptNonce, errDecryptNonce := hex.DecodeString(*inputNonce)
			if errDecryptNonce != nil {
				os.Exit(1)
			}
			if *verbose {
			}

			var errDecryptedBytes error
			decryptedBytes, errDecryptedBytes = gcm.Open(nil, decryptNonce, shellcode, nil)
			if errDecryptedBytes != nil {
				os.Exit(1)
			}
		case "XOR":
			// https://kylewbanks.com/blog/xor-encryption-using-go
			if *verbose {
			}
			decryptedBytes = make([]byte, len(shellcode))
			tempKey := *key
			for k, v := range shellcode {
				decryptedBytes[k] = v ^ tempKey[k%len(tempKey)]
			}
		case "RC4":
			if *verbose {
			}
			cipher, err := rc4.NewCipher([]byte(*key))
			if err != nil {
				os.Exit(1)
			}
			decryptedBytes = make([]byte, len(shellcode))
			cipher.XORKeyStream(decryptedBytes, shellcode)
		default:
			os.Exit(1)
		}
		if len(decryptedBytes) <= 0 {
			os.Exit(1)
		}
		if *b64 {
			outputBytes = make([]byte, base64.StdEncoding.EncodedLen(len(decryptedBytes)))
			base64.StdEncoding.Encode(outputBytes, decryptedBytes)
		} else {
			outputBytes = append(outputBytes, decryptedBytes...)
		}
	}

	if *verbose {
		if *b64 {
			fmt.Println(fmt.Sprintf("%s", outputBytes))
		} else {
			fmt.Println(fmt.Sprintf("%x", outputBytes))
		}
	}

	// Write the file
	err := ioutil.WriteFile(*output, outputBytes, 0660)
	if err != nil {
		os.Exit(1)
	}

}