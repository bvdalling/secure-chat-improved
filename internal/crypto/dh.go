package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// DH parameters - in production use larger, well-known safe primes
var (
	// 2048-bit MODP Group from RFC 3526
	Prime, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	Generator = big.NewInt(2)
)

// DHKey represents a Diffie-Hellman key pair
type DHKey struct {
	Private *big.Int
	Public  *big.Int
}

// GenerateDHKeys generates a new DH key pair
func GenerateDHKeys() (*DHKey, error) {
	// Generate a random private key
	privateKey, err := rand.Int(rand.Reader, Prime)
	if err != nil {
		return nil, err
	}

	// Calculate public key: g^private mod p
	publicKey := new(big.Int).Exp(Generator, privateKey, Prime)

	return &DHKey{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

// ComputeSharedSecret calculates the shared secret from our private key and their public key
func ComputeSharedSecret(privateKey, peerPublicKey *big.Int) []byte {
	// Calculate shared secret: (peer_public)^private mod p
	sharedSecret := new(big.Int).Exp(peerPublicKey, privateKey, Prime)

	// Convert to bytes and hash it to get a suitable encryption key
	sharedBytes := sharedSecret.Bytes()
	hash := sha256.Sum256(sharedBytes)

	return hash[:]
}
