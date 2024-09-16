package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"errors"
)

// Constants
const (
	WalletCryptoKeySize = 32 // AES256 key size in bytes
	WalletCryptoIVSize  = 16 // AES block size in bytes
)

// CCrypter struct to hold key and IV
type CCrypter struct {
	Key    []byte
	IV     []byte
	KeySet bool
}

// BytesToKeySHA512AES derives key and IV using SHA-512
func (c *CCrypter) BytesToKeySHA512AES(vch, salt []byte, count int) error {
	if count < 1 || len(vch) == 0 || len(salt) == 0 {
		return errors.New("invalid parameters")
	}

	// Initial hash
	hash := sha512.New()
	hash.Write(vch)
	hash.Write(salt)
	keyIV := hash.Sum(nil)

	for i := 1; i < count; i++ {
		hash.Reset()
		hash.Write(keyIV)
		keyIV = hash.Sum(nil)
	}

	c.Key = keyIV[:WalletCryptoKeySize]
	c.IV = keyIV[WalletCryptoKeySize : WalletCryptoKeySize+WalletCryptoIVSize]
	c.KeySet = true

	return nil
}

// SetKeyFromPassphrase sets the key and IV from a passphrase
func (c *CCrypter) SetKeyFromPassphrase(vch, salt []byte, rounds uint) bool {
	if rounds < 1 || len(salt) != WalletCryptoIVSize {
		return false
	}

	err := c.BytesToKeySHA512AES(vch, salt, int(rounds))
	if err != nil || len(c.Key) != WalletCryptoKeySize || len(c.IV) != WalletCryptoIVSize {
		return false
	}

	return true
}

// SetKey sets the key and IV directly
func (c *CCrypter) SetKey(newKey, newIV []byte) bool {
	if len(newKey) != WalletCryptoKeySize || len(newIV) != WalletCryptoIVSize {
		return false
	}

	c.Key = make([]byte, WalletCryptoKeySize)
	c.IV = make([]byte, WalletCryptoIVSize)
	copy(c.Key, newKey)
	copy(c.IV, newIV)
	c.KeySet = true

	return true
}

// Encrypt encrypts plaintext using AES-256-CBC
func (c *CCrypter) Encrypt(plaintext []byte) ([]byte, bool) {
	if !c.KeySet {
		return nil, false
	}

	// Ensure plaintext length is a multiple of block size
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	if padding > 0 {
		plaintext = append(plaintext, make([]byte, padding)...)
	}

	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, false
	}

	ciphertext := make([]byte, len(plaintext))
	encrypter := cipher.NewCBCEncrypter(block, c.IV)
	encrypter.CryptBlocks(ciphertext, plaintext)
	memoryCleanse(plaintext) // Clear plaintext after encryption
	return ciphertext, true
}

// Decrypt decrypts ciphertext using AES-256-CBC
func (c *CCrypter) Decrypt(ciphertext []byte) ([]byte, bool) {
	if !c.KeySet {
		return nil, false
	}

	// Ensure ciphertext length is a multiple of block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, false
	}

	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, false
	}

	plaintext := make([]byte, len(ciphertext))
	decrypter := cipher.NewCBCDecrypter(block, c.IV)
	decrypter.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	padding := plaintext[len(plaintext)-1]
	if int(padding) > aes.BlockSize || padding > byte(len(plaintext)) {
		return nil, false
	}
	plaintext = plaintext[:len(plaintext)-int(padding)]

	memoryCleanse(ciphertext) // Clear ciphertext after decryption
	return plaintext, true
}

// EncryptSecret encrypts a secret with a master key and IV
func EncryptSecret(masterKey, plaintext []byte, iv [WalletCryptoIVSize]byte) ([]byte, bool) {
	c := &CCrypter{}
	if !c.SetKey(masterKey, iv[:]) {
		return nil, false
	}
	return c.Encrypt(plaintext)
}

// DecryptSecret decrypts a secret with a master key and IV
func DecryptSecret(masterKey, ciphertext []byte, iv [WalletCryptoIVSize]byte) ([]byte, bool) {
	c := &CCrypter{}
	if !c.SetKey(masterKey, iv[:]) {
		return nil, false
	}
	return c.Decrypt(ciphertext)
}

// EncryptSecretFromKey encrypts a secret with a master key and IV
func EncryptSecretFromKey(masterKey []byte, plaintext []byte, iv [WalletCryptoIVSize]byte) ([]byte, bool) {
	c := &CCrypter{}
	if !c.SetKey(masterKey, iv[:]) {
		return nil, false
	}
	return c.Encrypt(plaintext)
}

// DecryptSecretFromKey decrypts a secret with a master key and IV
func DecryptSecretFromKey(masterKey []byte, ciphertext []byte, iv [WalletCryptoIVSize]byte) ([]byte, bool) {
	c := &CCrypter{}
	if !c.SetKey(masterKey, iv[:]) {
		return nil, false
	}
	return c.Decrypt(ciphertext)
}

// memoryCleanse overwrites sensitive data in memory
func memoryCleanse(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
