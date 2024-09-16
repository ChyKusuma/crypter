package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"math/big"
)

// Constants defining sizes for cryptographic operations
const (
	WALLET_CRYPTO_KEY_SIZE  = 32            // Size of the cryptographic key
	WALLET_CRYPTO_IV_SIZE   = 16            // Size of the Initialization Vector (IV) for AES
	WALLET_CRYPTO_SALT_SIZE = 16            // Size of the salt used in key derivation
	AES_BLOCKSIZE           = aes.BlockSize // Block size for AES encryption
)

// Type definitions for cryptographic operations and key management
type SecureString string    // A secure string used for key derivation
type CKeyingMaterial []byte // A type representing keying material (byte slice)
type uint256 struct {       // A type representing a 256-bit unsigned integer using math/big
	value *big.Int
}

type CPubKey struct{} // Placeholder for a public key type
type CKey struct {
	// CKey holds key data and methods to set and verify the key
	data []byte // Key data
}

// Struct for cryptographic operations
type CCrypter struct {
	vchKey  CKeyingMaterial // Key used for encryption/decryption
	vchIV   CKeyingMaterial // IV used for encryption/decryption
	fKeySet bool            // Flag indicating whether the key has been set
}

// Derives a key and IV from a passphrase using SHA-512 and AES
func bytesToKeySHA512AES(salt []byte, keyData SecureString, count int, key, iv []byte) int {
	if count == 0 || len(key) == 0 || len(iv) == 0 {
		return 0 // Invalid input, return 0
	}

	// Create a new SHA-512 hash
	h := sha512.New()
	h.Write([]byte(keyData)) // Write the key data to the hash
	h.Write(salt)            // Write the salt to the hash
	buf := h.Sum(nil)        // Get the hash sum

	// Perform multiple iterations of hashing
	for i := 1; i < count; i++ {
		h.Reset()        // Reset the hash
		h.Write(buf)     // Write the previous hash result
		buf = h.Sum(nil) // Get the new hash sum
	}

	// Copy derived key and IV from the final hash result
	copy(key, buf[:WALLET_CRYPTO_KEY_SIZE])
	copy(iv, buf[WALLET_CRYPTO_KEY_SIZE:WALLET_CRYPTO_KEY_SIZE+WALLET_CRYPTO_IV_SIZE])

	return WALLET_CRYPTO_KEY_SIZE // Return the size of the derived key
}

// Set the key and IV from a passphrase using a key derivation method
func (c *CCrypter) SetKeyFromPassphrase(keyData SecureString, salt []byte, rounds uint, derivationMethod uint) bool {
	if rounds < 1 || len(salt) != WALLET_CRYPTO_SALT_SIZE {
		return false // Invalid rounds or salt size, return false
	}

	// Use the specified key derivation method
	if derivationMethod == 0 {
		n := bytesToKeySHA512AES(salt, keyData, int(rounds), c.vchKey, c.vchIV)
		if n != WALLET_CRYPTO_KEY_SIZE {
			c.memoryCleanse(c.vchKey) // Cleanse memory on failure
			c.memoryCleanse(c.vchIV)
			return false // Derivation failed, return false
		}
	}

	c.fKeySet = true // Indicate that the key is set
	return true      // Return true on success
}

// Set the key and IV directly
func (c *CCrypter) SetKey(newKey CKeyingMaterial, newIV []byte) bool {
	if len(newKey) != WALLET_CRYPTO_KEY_SIZE || len(newIV) != WALLET_CRYPTO_IV_SIZE {
		return false // Invalid key or IV size, return false
	}

	copy(c.vchKey, newKey) // Copy the new key
	copy(c.vchIV, newIV)   // Copy the new IV

	c.fKeySet = true // Indicate that the key is set
	return true      // Return true on success
}

// Encrypt plaintext using AES with CBC mode
func (c *CCrypter) Encrypt(plaintext CKeyingMaterial) ([]byte, bool) {
	if !c.fKeySet {
		return nil, false // Key not set, return false
	}

	ciphertext := make([]byte, len(plaintext)+AES_BLOCKSIZE) // Allocate buffer for ciphertext

	block, err := aes.NewCipher(c.vchKey) // Create a new AES cipher with the key
	if err != nil {
		return nil, false // Error creating cipher, return false
	}

	mode := cipher.NewCBCEncrypter(block, c.vchIV) // Create a CBC encrypter
	mode.CryptBlocks(ciphertext, plaintext)        // Encrypt the plaintext
	return ciphertext[:len(plaintext)], true       // Return the ciphertext and true on success
}

// Decrypt ciphertext using AES with CBC mode
func (c *CCrypter) Decrypt(ciphertext []byte) (CKeyingMaterial, bool) {
	if !c.fKeySet {
		return nil, false // Key not set, return false
	}

	plaintext := make([]byte, len(ciphertext)) // Allocate buffer for plaintext

	block, err := aes.NewCipher(c.vchKey) // Create a new AES cipher with the key
	if err != nil {
		return nil, false // Error creating cipher, return false
	}

	mode := cipher.NewCBCDecrypter(block, c.vchIV) // Create a CBC decrypter
	mode.CryptBlocks(plaintext, ciphertext)        // Decrypt the ciphertext
	return plaintext, true                         // Return the plaintext and true on success
}

// Encrypt a secret using a master key and an IV
func EncryptSecret(masterKey CKeyingMaterial, plaintext CKeyingMaterial, iv uint256, ciphertext []byte) bool {
	var cKeyCrypter CCrypter                         // Create a new CCrypter instance
	chIV := iv.value.Bytes()[:WALLET_CRYPTO_IV_SIZE] // Extract the IV from the uint256

	if !cKeyCrypter.SetKey(masterKey, chIV) {
		return false // Failed to set the key, return false
	}

	encText, ok := cKeyCrypter.Encrypt(plaintext) // Encrypt the plaintext
	if !ok {
		return false // Encryption failed, return false
	}

	if len(ciphertext) < len(encText) {
		return false // Buffer too small, return false
	}

	copy(ciphertext, encText) // Copy the encrypted text to the output buffer
	return true               // Return true on success
}

// Decrypt a secret using a master key and an IV
func DecryptSecret(masterKey CKeyingMaterial, ciphertext []byte, iv uint256, plaintext []byte) bool {
	var cKeyCrypter CCrypter                         // Create a new CCrypter instance
	chIV := iv.value.Bytes()[:WALLET_CRYPTO_IV_SIZE] // Extract the IV from the uint256

	if !cKeyCrypter.SetKey(masterKey, chIV) {
		return false // Failed to set the key, return false
	}

	decrypted, ok := cKeyCrypter.Decrypt(ciphertext) // Decrypt the ciphertext
	if !ok {
		return false // Decryption failed, return false
	}

	if len(plaintext) < len(decrypted) {
		return false // Buffer too small, return false
	}

	copy(plaintext, decrypted) // Copy the decrypted text to the output buffer
	return true                // Return true on success
}

// Decrypt a key from a master key and an encrypted secret
func DecryptKey(masterKey CKeyingMaterial, cryptedSecret []byte, pubKey CPubKey) (CKey, bool) {
	// Allocate a buffer for the plaintext
	plaintext := make([]byte, len(cryptedSecret))

	// Call DecryptSecret with the buffer for plaintext
	ok := DecryptSecret(masterKey, cryptedSecret, pubKey.GetHash(), plaintext)
	if !ok {
		return CKey{}, false // Decryption failed, return an empty key and false
	}

	if len(plaintext) != 32 {
		return CKey{}, false // Secret length is not 32 bytes, return an empty key and false
	}

	var key CKey                              // Create a new CKey instance
	key.Set(plaintext, pubKey.IsCompressed()) // Set the key data
	if !key.VerifyPubKey(pubKey) {
		return CKey{}, false // Public key verification failed, return an empty key and false
	}

	return key, true // Return the key and true on success
}

// Cleanse memory by setting all bytes to zero
func (c *CCrypter) memoryCleanse(data CKeyingMaterial) {
	for i := range data {
		data[i] = 0 // Set each byte to zero
	}
}

// Placeholder method for CPubKey to get the hash
func (p *CPubKey) GetHash() uint256 {
	return uint256{value: new(big.Int)} // Placeholder implementation
}

// Placeholder method for CPubKey to check if the key is compressed
func (p *CPubKey) IsCompressed() bool {
	return false // Placeholder implementation
}

// Placeholder method for CKey to set key data
func (k *CKey) Set(data []byte, compressed bool) {
	k.data = data // Set the key data
}

// Placeholder method for CKey to verify public key
func (k *CKey) VerifyPubKey(pubKey CPubKey) bool {
	return true // Placeholder implementation
}
