package NetEaseX19Sing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	//密匙固定长度
	KeySize = 32
	//网易默认密匙
	NetEasePassword = "942894570397f6d1c9cca2535ad18a2b"
)

type Cipher struct {
	Key string
}

func New(Key string) (*Cipher, error) {
	var c Cipher
	if len(Key) != KeySize {
		return nil, errors.New("密匙不为32位")
	}
	c.Key = Key
	return &c, nil
}

// 解密
func (c *Cipher) X19SingDecrypt(data string) (string, error) {
	if len(data) < 64 {
		return "", errors.New("数据最少64位")
	}
	if len(data)%16 != 0 {
		return "", errors.New("数据格式错误")
	}
	body := DeIntToStr(PeDecrypt(DecryptStr2int64(data), toLongArray(PadRight([]byte(c.Key)))))
	return body, nil
}

// 加密
func (c *Cipher) X19SingEncryptio(data string) (string, error) {
	if len(data) == 0 {
		return "", errors.New("数据错误")
	}
	body := IntToStr(PeEncryption(toLongArray(PadRight([]byte(data))), toLongArray(PadRight([]byte(c.Key)))))
	return body, nil
}

func SingPeDecrypt(str string) string {
	body := DeIntToStr(PeDecrypt(DecryptStr2int64(str), toLongArray(PadRight([]byte(NetEasePassword)))))
	return body
}

func myParseInt(hexStr string) int64 {
	var result int64
	for i := range hexStr {
		value := hexCharToValue(hexStr[i])
		if value == -1 {
			return 0
		}
		result = result*16 + int64(value)
	}
	return result
}

func hexCharToValue(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

func DecryptStr2int64(fdh string) []int64 {
	num := len(fdh) / 16
	array := make([]int64, num)
	for i := 0; i < num; i++ {
		val := myParseInt(fdh[i*16 : i*16+16])
		array[i] = val
	}
	return array
}

func PeDecrypt(fdc, fdd []int64) []int64 {
	num := len(fdc)
	if num < 1 {
		return fdc
	}
	num2 := fdc[num-1]
	num3 := fdc[0]
	num4 := int64(6 + 52/num)
	for num5 := num4 * 2654435769; num5 != 0; num5 -= 2654435769 {
		num6 := num5 >> 2 & 3
		var num7 int64
		for num7 = int64(num - 1); num7 > 0; num7-- {
			num2 = fdc[num7-1]
			fdc[num7] -= ((num2>>5 ^ num3<<2) + (num3>>3 ^ num2<<4) ^ ((num5 ^ num3) + (fdd[(num7&3^num6)] ^ num2)))
			num3 = fdc[num7]
		}
		num2 = fdc[num-1]
		fdc[0] -= ((num2>>5 ^ num3<<2) + (num3>>3 ^ num2<<4) ^ ((num5 ^ num3) + (fdd[(num7&3^num6)] ^ num2)))
		num3 = fdc[0]
	}
	return fdc
}

func DeIntToStr(fdf []int64) string {
	list := make([]byte, 0, len(fdf)*8)
	for _, v := range fdf {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(v))
		list = append(list, b...)
	}
	for len(list) > 0 && list[len(list)-1] == 0 {
		list = list[:len(list)-1]
	}
	return string(list)
}

func SingPeEncryption(data string) string {
	body := IntToStr(PeEncryption(toLongArray(PadRight([]byte(data))), toLongArray(PadRight([]byte(NetEasePassword)))))
	return body
}

func PadRight(bodyIn []byte) []byte {
	if len(bodyIn) > 32 {
		return bodyIn
	}
	body := make([]byte, func(s int) int {
		if s%32 != 0 {
			return s + 32 - s%32
		}
		return s
	}(len(bodyIn)))
	copy(body, bodyIn)
	return body
}

func toLongArray(b []byte) []int64 {
	num := (len(b) + 7) / 8
	arr := make([]int64, num)
	for i := 0; i < num-1; i++ {
		arr[i] = int64(binary.LittleEndian.Uint64(b[i*8:]))
	}
	lastBytes := make([]byte, 8)
	copy(lastBytes, b[(num-1)*8:])
	arr[num-1] = int64(binary.LittleEndian.Uint64(lastBytes))

	return arr
}

func PeEncryption(fda []int64, fdb []int64) []int64 {
	num := len(fda)
	if num < 1 {
		return fda
	}
	num2 := fda[num-1]
	num3 := fda[0]
	num4 := int64(0)
	num5 := int64(6 + 52/num)
	for ; num5 > 0; num5-- {
		num4 += int64(2654435769)
		num7 := (num4 >> 2) & 3
		var num8 int64
		for num8 = 0; num8 < int64(num-1); num8++ {
			num3 = fda[num8+1]
			fda[num8] += ((num2>>5 ^ num3<<2) + (num3>>3 ^ num2<<4) ^ ((num4 ^ num3) + (fdb[(num8&3)^num7] ^ num2)))
			num2 = fda[num8]
		}
		num3 = fda[0]
		fda[num-1] += ((num2>>5 ^ num3<<2) + (num3>>3 ^ num2<<4) ^ ((num4 ^ num3) + (fdb[(num8&3)^num7] ^ num2)))
		num2 = fda[num-1]
	}
	return fda
}

func IntToStr(fdg []int64) string {
	var stringBuilder strings.Builder
	for _, v := range fdg {
		stringBuilder.WriteString(fmt.Sprintf("%016x", uint64(v)))
	}
	return stringBuilder.String()
}
