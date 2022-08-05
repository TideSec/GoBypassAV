package main

import (
	"fmt"
	"github.com/darkwyrm/b85"
)

func main(){
	var str = "tidesec"
	strbytes := []byte(str)
	encode := b85.Encode(strbytes)
	decode,_ := b85.Decode(encode)

	fmt.Printf("加密数据: %v \n", str)
	fmt.Printf("加密结果: %v \n", encode)
	fmt.Printf("解密结果: %v \n", string(decode))
}
