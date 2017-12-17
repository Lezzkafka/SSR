# Abstract
This document describes how to define entities in a Spaco network


# Motivation

The current Internet hardware and software architecture in the design of some fundamental problems, such as:
* ip / port exposes personal privacy
* Third parties in the network can easily forge other's IP
* ARP spoofing occurs in the LAN
* DNS will be hijacked
* Service providers will  be forged


# Specification

In the Spaco network, we believe that any device, software, or individual needs to be able to prove who he is, and no one can forge others' identities, so we agree:
In the network, any person equipment, software, personal, services need to use public key system to identify.

* The public key address equals the current Internet IP address in the Spaco network.
* The public key address can also be the device, the software's blockchina wallet address
* The public key address is also the service address

The sender of the data should sign the data sent. The recipient of the data needs to verify the data received. Once the data sent by the sender and the signature do not match, the sender of the data should be included in the list of suspicious or black List.

The wallet address can be generated from the public key address


# Backward compatibility

# Implementation

* Public key generation algorithm

```
// GenerateKeyPair creates key pair
func GenerateKeyPair() (PubKey, SecKey) {
	public, secret := secp256k1.GenerateKeyPair()

	if DebugLevel1 {
		if TestSecKey(NewSecKey(secret)) != nil {
			logger.Panic("DebugLevel1, GenerateKeyPair, generated private key " +
				"failed TestSecKey")
		}
	}

	return NewPubKey(public), NewSecKey(secret)
}

// GenerateDeterministicKeyPair generates deterministic key pair
func GenerateDeterministicKeyPair(seed []byte) (PubKey, SecKey) {
	public, secret := secp256k1.GenerateDeterministicKeyPair(seed)

	if DebugLevel1 {

		if TestSecKey(NewSecKey(secret)) != nil {
			logger.Panic("DebugLevel1, GenerateDeterministicKeyPair, " +
				"seckey invalid, failed TestSecKey")
		}
		if TestSecKey(NewSecKey(secret)) != nil {
			logger.Panic("DebugLevel1, GenerateDeterministicKeyPair, " +
				"generated private key failed TestSecKey")
		}
		if PubKeyFromSecKey(NewSecKey(secret)) != NewPubKey(public) {
			logger.Panic("DebugLevel1, GenerateDeterministicKeyPair, " +
				"public key does not match private key")
		}
	}
	return NewPubKey(public), NewSecKey(secret)
}
```


* Spaco wallet address generation algorithm

```
func SpoAddressFromPubKey(pubkey PubKey) s```tring {
	b1 := SumSHA256(pubkey[:])
	b2 := HashRipemd160(b1[:])
	b3 := append([]byte{byte(0)}, b2[:]...)
	b4 := DoubleSHA256(b3)
	b5 := append(b3, b4[0:4]...)
	return string(base58.Hex2Base58(b5))
}
```

* data verification


```
// VerifySignature verifies that hash was signed by PubKey
func VerifySignature(pubkey PubKey, sig Sig, hash SHA256) error {
	pubkeyRec, err := PubKeyFromSig(sig, hash) //recovered pubkey
	if err != nil {
		return errors.New("Invalid sig: PubKey recovery failed")
	}
	if pubkeyRec != pubkey {
		return errors.New("Recovered pubkey does not match pubkey")
	}
	if secp256k1.VerifyPubkey(pubkey[:]) != 1 {
		if DebugLevel2 {
			if secp256k1.VerifySignature(hash[:], sig[:], pubkey[:]) == 1 {
				logger.Panic("VerifySignature warning, ")
			}
		}
		return errors.New("VerifySignature, secp256k1.VerifyPubkey failed")
	}
	if secp256k1.VerifySignatureValidity(sig[:]) != 1 {
		return errors.New("VerifySignature, VerifySignatureValidity failed")
	}
	if secp256k1.VerifySignature(hash[:], sig[:], pubkey[:]) != 1 {
		return errors.New("Invalid signature for this message")
	}
	return nil
}
```



# reference
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
