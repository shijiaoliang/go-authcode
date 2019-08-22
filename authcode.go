/**
 *******************************************slade********************************************
 * Copyright (c)  slade
 * Created by my-gin.
 * User: 605724193@qq.com
 * Date: 2019/08/07
 * Time: 11:18
 ********************************************************************************************
 */

package main

import (
	"fmt"
	"strings"
	"time"
	"strconv"
	"crypto/md5"
	"encoding/hex"
	"encoding/base64"
)

func authCode(str, operation, key string, expiry int64) string {
	if operation == "DECODE" {
		str = strings.Replace(str, "[a]", "+", -1)
		str = strings.Replace(str, "[b]", "&", -1)
		str = strings.Replace(str, "[c]", "/", -1)
	}

	cKeyLength := 4
	// 随机密钥长度 取值 0-32;
	// 加入随机密钥，可以令密文无任何规律，即便是原文和密钥完全相同，加密结果也会每次不同，增大破解难度。
	// 取值越大，密文变动规律越大，密文变化 = 16 的 $cKeyLength 次方
	// 当此值为 0 时，则不产生随机密钥

	if key == "" {
		key = "key"
	}
	key = md5String(key)

	// 密匙a会参与加解密
	keyA := md5String(key[:16])
	// 密匙b会用来做数据完整性验证
	keyB := md5String(key[16:])
	// 密匙c用于变化生成的密文
	keyC := ""
	//if cKeyLength != 0 {
		if operation == "DECODE" {
			keyC = str[:cKeyLength]
		} else {
			sTime := md5String(time.Now().String())
			sLen := 32 - cKeyLength
			keyC = sTime[sLen:]
		}
	//}

	// 参与运算的密匙
	cryptKey := fmt.Sprintf("%s%s", keyA, md5String(keyA+keyC))
	keyLength := len(cryptKey)

	// 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$keyB(密匙b)，解密时会通过这个密匙验证数据完整性
	// 如果是解码的话，会从第cKeyLength位开始，因为密文前cKeyLength位保存 动态密匙，以保证解密正确
	if operation == "DECODE" {
		strByte, _ := base64.RawStdEncoding.DecodeString(str[cKeyLength:])
		str = string(strByte)
	} else {
		if expiry != 0 {
			expiry = expiry + time.Now().Unix()
		}

		tmpMd5 := md5String(str + keyB)
		str = fmt.Sprintf("%010d%s%s", expiry, tmpMd5[:16], str)
	}

	stringLength := len(str)
	resData := make([]byte, 0, stringLength)
	var rndKey, box [256]int

	// 产生密匙簿
	j := 0
	a := 0
	i := 0
	tmp := 0
	for i = 0; i < 256; i++ {
		rndKey[i] = int(cryptKey[i%keyLength])
		box[i] = i
	}
	// 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上并不会增加密文的强度
	for i = 0; i < 256; i ++ {
		j = (j + box[i] + rndKey[i]) % 256
		tmp = box[i]
		box[i] = box[j]
		box[j] = tmp
	}
	// 核心加解密部分
	a = 0
	j = 0
	tmp = 0
	for i = 0; i < stringLength; i++ {
		a = (a + 1) % 256
		j = (j + box[a]) % 256
		tmp = box[a]
		box[a] = box[j]
		box[j] = tmp

		// 从密匙簿得出密匙进行异或，再转成字符
		resData = append(resData, byte(int(str[i])^box[(box[a]+box[j])%256]))
	}
	result := string(resData)

	if operation == "DECODE" {
		// 验证数据有效性，请看未加密明文的格式
		frontTen, _ := strconv.ParseInt(result[:10], 10, 0)
		if (frontTen == 0 || frontTen-time.Now().Unix() > 0) && result[10:26] == md5String(result[26:] + keyB)[:16] {
			return result[26:]
		} else {
			return ""
		}
	} else {
		// 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因
		// 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码
		result = keyC + base64.RawStdEncoding.EncodeToString([]byte(result))

		result = strings.Replace(result, "=", "", -1)
		result = strings.Replace(result, "+", "[a]", -1)
		result = strings.Replace(result, "&", "[b]", -1)
		result = strings.Replace(result, "/", "[c]", -1)

		return result
	}
}

func md5String(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	str := "let's golang"
	encode := authCode(str, "ENCODE", "", 0)
	fmt.Println(encode)

	decode := authCode(encode, "DECODE", "", 0)
	fmt.Println(decode)
}
