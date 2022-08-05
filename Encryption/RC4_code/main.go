package main

import (
	"crypto/rc4"
	"fmt"
	"log"
)

func rc4encode(shellcode []byte, key []byte) []byte {
	cipher, err := rc4.NewCipher(key)
	if err != nil {

	}
	encryptedBytes := make([]byte, len(shellcode))
	cipher.XORKeyStream(encryptedBytes, shellcode)
	return encryptedBytes
}

func rc4decode(shellcode []byte, key []byte) []byte {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		log.Println(err)
	}
	decryptedBytes := make([]byte, len(shellcode))
	cipher.XORKeyStream(decryptedBytes, shellcode)
	return decryptedBytes
}

func main(){
	key := []byte("TideSec")
	data := []byte("Hello Tide")
	s := rc4encode(data, key)
	fmt.Printf("加密密钥: %v \n", string(key))
	fmt.Printf("加密数据: %v \n", string(data))
	fmt.Printf("加密结果: %v \n", s)
	d := rc4decode(s, key)
	fmt.Printf("解密结果: %v \n", string(d))
}
