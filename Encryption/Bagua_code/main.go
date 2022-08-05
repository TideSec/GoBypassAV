package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	qian = "☰" // 乾
	dui  = "☱" // 兑
	li   = "☲" // 离
	zhen = "☳" // 震
	xun  = "☴" // 巽
	kan  = "☵" // 坎
	gen  = "☶" // 艮
	kun  = "☷" // 坤
)

var m1 = map[int]string{
	0: qian,
	1: dui,
	2: li,
	3: zhen,
	4: xun,
	5: kan,
	6: gen,
	7: kun,
}

var m2 = map[string][3]int{
	qian: {0, 0, 0},
	dui:  {0, 0, 1},
	li:   {0, 1, 0},
	zhen: {0, 1, 1},
	xun:  {1, 0, 0},
	kan:  {1, 0, 1},
	gen:  {1, 1, 0},
	kun:  {1, 1, 1},
}

func encode(src []byte) string {
	bs := make([]int, len(src)*8)
	bl := len(bs)
	for k, v := range src {
		byteTo2(int(v), bs[k*8:k*8+8])
	}

	buf := make([]string, (bl+2)/3)
	for i := 0; i*3+2 < len(bs); i++ {
		buf[i] = m1[bs[i*3]<<2+bs[i*3+1]<<1+bs[i*3+2]]
	}

	switch bl % 3 {
	case 1:
		buf[(bl+2)/3-1] = m1[bs[bl-1]<<2]
	case 2:
		buf[(bl+2)/3-1] = m1[bs[bl-2]<<2+bs[bl-1]<<1]
	}

	return strings.Join(buf, "")
}

func decode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}

	sl := len(s)

	is := make([]int, sl)
	for i := 0; i < sl/3; i++ {
		b, ok := m2[s[i*3:i*3+3]]
		if !ok {
			return nil, errors.New("invalid string, cur: " + strconv.Itoa(i))
		}
		copy(is[i*3:i*3+3], b[:])
	}

	buf := make([]byte, sl/8)
	for i := 0; i < sl/8; i++ {
		buf[i] = b8ToByte(is[i*8 : i*8+8])
	}

	return buf, nil
}

func b8ToByte(b []int) byte {
	return byte(b[0]<<7 + b[1]<<6 + b[2]<<5 + b[3]<<4 + b[4]<<3 + b[5]<<2 + b[6]<<1 + b[7])
}

func byteTo2(byt int, dst []int) {
	var i = 7
	for byt != 0 {
		dst[i] = byt % 2
		byt = byt >> 1
		i--
	}
	return
}

//加密
func Bagua_en(s []byte) string {
	result := encode(s)
	return result
}

//解密
func Bagua_de(s string) []byte {
	result, err := decode(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	return result
}

func main(){
	var str = "tidesec"
	strbytes := []byte(str)
	s := Bagua_en(strbytes)
	d := Bagua_de(s)
	fmt.Printf("加密数据: %v \n", str)
	fmt.Printf("加密结果: %v \n", s)
	fmt.Printf("解密结果: %v \n", string(d))
}