package main

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"crypto/des"
	"fmt"
)

func main() {
	plaintext := "hello"
	key := "100000000000001111000101000001010100000111000000100000000011100001011000011010001000101111110101000000100000111111000011000000100100001000100001100010000001000010100000111000010110000110100011011"
	iv := "1001000000000011000001010000011000000011000010111000100010000110"

	keyByte := BinaryStringToByte(key)
	ivByte := BinaryStringToByte(iv)
	
	encrypted, errEnc := encrypt(plaintext, keyByte, ivByte)
	if errEnc != nil {
		fmt.Println(errEnc)
	}
	decrypted, errDec := decrypt(encrypted, keyByte, ivByte)
	if errDec != nil {
		fmt.Println(errDec)
	}
	fmt.Printf("encrypted is : %s and decrypted is : %s", encrypted, decrypted)
}


func encrypt(plaintext string, key, iv []byte) (string, error) {

	plaintextByte := []byte(plaintext)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", nil
	}

	if len(plaintext)%block.BlockSize() != 0 {
		plaintextByte = PKCS7Pad(plaintextByte, block.BlockSize())
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(plaintextByte))
	mode.CryptBlocks(encrypted, plaintextByte)
	
	encryptString := fmt.Sprintf("%x", encrypted)
	decodedEncryptedHex, err := hex.DecodeString(encryptString)
	if err != nil {
		return "", nil
	}
	base64Encrypted := base64.StdEncoding.EncodeToString(decodedEncryptedHex)

	return base64Encrypted, nil

}

func decrypt(ciphertext string, key, iv []byte ) (string, error) {

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", nil
	}

	base64Decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", nil
	}
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(base64Decoded))
	decrypter.CryptBlocks(decrypted, base64Decoded)
	decrypted = PKCS7UnPad(decrypted)

	return string(decrypted), nil
}

func PKCS7Pad(unpadded []byte, blockSize int) []byte {
	padding := (blockSize - len(unpadded)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(unpadded, padtext...)
}

// Undo removes PKCS7 padding
func PKCS7UnPad(padded []byte) []byte {
	length := len(padded)
	unpadding := int(padded[length-1])
	return padded[:(length - unpadding)]
}

func  BinaryStringToByte(binary string) []byte {
	var outputByte []byte
	var str string

	for i := len(binary); i > 0; i -= 8 {
		if i-8 < 0 {
			str = string(binary[0:i])
		} else {
			str = string(binary[i-8 : i])
		}
		v, err := strconv.ParseUint(str, 2, 8)
		if err != nil {
			panic(err)
		}
		outputByte = append([]byte{byte(v)}, outputByte...)
	}
	return outputByte
}

func BinaryStringToHexByte(binary string) []string {
	var out []string
	byteSlice := BinaryStringToByte(binary)
	for _, b := range byteSlice {
		out = append(out, "0x"+hex.EncodeToString([]byte{b}))
	}
	return out
}
