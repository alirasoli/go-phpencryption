package phpencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type PHPEncryption struct {
	encryptionKey []byte
}

func NewPHPEncryption(encryptionKey []byte) PHPEncryption {
	return PHPEncryption{
		encryptionKey: encryptionKey,
	}
}

const (
	headerVersionSize     = 4
	minimumCiphertextSize = 84
	saltByteSize          = 32
	blockByteSize         = 16
	macByteSize           = 32
)

func (e PHPEncryption) Encrypt(data []byte) (string, error) {
	salt := make([]byte, saltByteSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	mac := make([]byte, macByteSize)
	if _, err := io.ReadFull(rand.Reader, mac); err != nil {
		return "", err
	}

	key := getEncryptionKey(e.encryptionKey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, blockByteSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	ctr := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(data))
	ctr.XORKeyStream(ciphertext, data)

	headerHex := "DEF50200"
	header, err := hex.DecodeString(headerHex)
	if err != nil {
		panic(err)
	}

	ciphertextWithHeader := append(header, salt...)
	ciphertextWithHeader = append(ciphertextWithHeader, iv...)
	ciphertextWithHeader = append(ciphertextWithHeader, ciphertext...)
	ciphertextWithHeader = append(ciphertextWithHeader, mac...)

	ciphertextHex := hex.EncodeToString(ciphertextWithHeader)
	return ciphertextHex, nil
}

func (e PHPEncryption) Decrypt(data string) ([]byte, error) {
	if len(data) < minimumCiphertextSize {
		return nil, errors.New("ciphertext is too short")
	}

	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}

	salt := ciphertext[headerVersionSize : headerVersionSize+saltByteSize]
	iv := ciphertext[headerVersionSize+saltByteSize : headerVersionSize+saltByteSize+blockByteSize]
	encrypted := ciphertext[headerVersionSize+saltByteSize+blockByteSize : headerVersionSize+saltByteSize+blockByteSize+len(ciphertext)-macByteSize-saltByteSize-blockByteSize-headerVersionSize]

	key := getEncryptionKey(e.encryptionKey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(block, iv)

	plaintext := make([]byte, len(encrypted))
	ctr.XORKeyStream(plaintext, encrypted)
	return plaintext, nil
}

func getEncryptionKey(secret []byte, salt []byte) []byte {
	hash := sha256.New

	h := sha256.New()
	h.Write(secret)
	prehash := h.Sum(nil)

	prekey := pbkdf2.Key(prehash, salt, 100_000, 32, hash)

	const info = "DefusePHP|V2|KeyForEncryption"
	hkdf := hkdf.New(hash, prekey, salt, []byte(info))

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}
