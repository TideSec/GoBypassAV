package main

import (
	"encoding/base64"
	"fmt"
)

func main(){
	var str = "tidesec"
	strbytes := []byte(str)
	encoded := base64.StdEncoding.EncodeToString(strbytes)
	fmt.Println(encoded)

	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	decodestr := string(decoded)
	fmt.Println(decodestr)
}
