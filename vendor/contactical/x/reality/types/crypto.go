package types

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// 블록 해시를 이용해서 챌린지 생성 (간단하게 Hex String 변환)
func GenerateChallengeFromBlockHash(blockHash []byte) string {
    // 안드로이드가 Base64를 쓰면 Base64로, Hex를 쓰면 Hex로 맞춰야 함
    // 여기서는 Base64로 통일한다고 가정
	return base64.StdEncoding.EncodeToString(blockHash)
}

// 데이터 서명 검증
func VerifyDataSignature(payload string, signatureBase64 string, certBase64 string) (bool, error) {
	// 1. 인증서 파싱
	certBytes, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return false, fmt.Errorf("cert decode failed: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return false, fmt.Errorf("cert parse failed: %v", err)
	}

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not ECDSA")
	}

	// 2. 서명 파싱
	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("signature decode failed: %v", err)
	}

	// 3. 검증
	hash := sha256.Sum256([]byte(payload))
	valid := ecdsa.VerifyASN1(pubKey, hash[:], sigBytes)

	return valid, nil
}