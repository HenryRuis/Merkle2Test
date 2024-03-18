package VedCrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 填充明文，确保其长度是块大小的整数倍
	blockSize := block.BlockSize()
	plaintext = pkcs7Pad(plaintext, blockSize)

	// 使用AES加密模式创建块模式
	mode := cipher.NewCBCEncrypter(block, key[:blockSize])

	// 创建一个缓冲区，用于存储加密结果
	ciphertext := make([]byte, len(plaintext))

	// 执行加密
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 使用AES解密模式创建块模式
	mode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])

	// 创建一个缓冲区，用于存储解密结果
	plaintext := make([]byte, len(ciphertext))

	// 执行解密
	mode.CryptBlocks(plaintext, ciphertext)

	// 去除填充
	plaintext = pkcs7Unpad(plaintext)

	return plaintext, nil
}

// pkcs7Pad对数据进行PKCS7填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7Unpad对PKCS7填充的数据进行去除填充
func pkcs7Unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

func main() {
	// 随机生成AES密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Println("Error generating random key:", err)
		return
	}

	// 要加密的数据
	plaintext := []byte("Hello, AES!")

	// 加密
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}

	fmt.Println("Encrypted:", hex.EncodeToString(ciphertext))

	// 解密
	decryptedText, err := Decrypt(ciphertext, key)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}

	fmt.Println("Decrypted:", string(decryptedText))
}
