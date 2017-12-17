# Abstract
本篇文档描述如何在Spaco网络中定义实体


# Motivation

当前互联网的软硬件体系结构在设计上存在一些根本上的问题，比如：
* ip/port暴露个人隐私
* 网络中的第三方很容易伪造他人的IP
* 局域网中会发生ARP欺骗 
* DNS会被人劫持
* 服务提供方会被伪造


# Specification

在Spaco网络中，我们认为，任何的设备、软件、个人都需要有能力证明自己是谁，任何人都不能伪造别人的标识，所以我们约定：
在网络中，任何人设备、软件、个人、服务都需要用公私钥体系来进行标识。

* 公钥地址在Spaco网络中等同于当前互联网上的IP地址。
* 公钥地址同时也可以是该设备、软件的blockchina钱包地址
* 公钥地址也是服务地址

数据的发送方应该对发出的数据进行数据签名，数据的接收方需要对收到的数据进行验证，一旦发送方发送的数据和签名不匹配，该数据的发送方应该被列入可疑名单或黑名单.

可以通过公钥地址生成钱包地址


# Backward compatibility

# Implementation

* 公钥生成算法

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


* Spaco钱包地址生成算法
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

* 数据验证

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
