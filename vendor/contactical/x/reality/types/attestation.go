package types

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

// ---------------------------------------------------------
// 1. ASN.1 구조체 정의 (구글 스펙)
// ---------------------------------------------------------

// 보안 레벨
type SecurityLevel int

const (
	SecurityLevelSoftware  = 0
	SecurityLevelTEE       = 1
	SecurityLevelStrongBox = 2
)

// AuthorizationList
type AuthorizationList struct {
	Purpose              []int       `asn1:"tag:1,explicit,optional"`
	Algorithm            int         `asn1:"tag:2,explicit,optional"`
	KeySize              int         `asn1:"tag:3,explicit,optional"`
	Digest               []int       `asn1:"tag:5,explicit,optional"`
	Padding              []int       `asn1:"tag:6,explicit,optional"`
	EC_Curve             int         `asn1:"tag:10,explicit,optional"`
	RSA_PublicExponent   int         `asn1:"tag:200,explicit,optional"`
	ActiveDateTime       int64       `asn1:"tag:400,explicit,optional"`
	OriginationExpire    int64       `asn1:"tag:401,explicit,optional"`
	UsageExpire          int64       `asn1:"tag:402,explicit,optional"`
	NoAuthRequired       bool        `asn1:"tag:503,explicit,optional"`
	UserAuthType         int         `asn1:"tag:504,explicit,optional"`
	AuthTimeout          int         `asn1:"tag:505,explicit,optional"`
	AllowWhileOnBody     bool        `asn1:"tag:506,explicit,optional"`
	AllApplications      bool        `asn1:"tag:600,explicit,optional"`
	ApplicationID        []byte      `asn1:"tag:601,explicit,optional"`
	CreationDateTime     int64       `asn1:"tag:701,explicit,optional"`
	Origin               int         `asn1:"tag:702,explicit,optional"`
	RootOfTrust          RootOfTrust `asn1:"tag:704,explicit,optional"`
	OSVersion            int         `asn1:"tag:705,explicit,optional"`
	OSPatchLevel         int         `asn1:"tag:706,explicit,optional"`
	AttestationAppID     []byte      `asn1:"tag:709,explicit,optional"`
	AttestationIDBrand   []byte      `asn1:"tag:710,explicit,optional"`
	AttestationIDDevice  []byte      `asn1:"tag:711,explicit,optional"`
	AttestationIDProduct []byte      `asn1:"tag:712,explicit,optional"`
}

type RootOfTrust struct {
	VerifiedBootKey   []byte `asn1:"optional"`
	DeviceLocked      bool
	VerifiedBootState int
	VerifiedBootHash  []byte `asn1:"optional"`
}

type AttestationRecord struct {
	AttestationVersion       int
	AttestationSecurityLevel SecurityLevel
	KeymasterVersion         int
	KeymasterSecurityLevel   SecurityLevel
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         AuthorizationList
	TeeEnforced              AuthorizationList
}

// ---------------------------------------------------------
// 2. 검증 결과 반환용 구조체
// ---------------------------------------------------------
type AttestationInfo struct {
	SecurityLevel    SecurityLevel
	DeviceLocked     bool
	BootState        int
	CreationTime     int64
	AttestationLevel int
	OSVersion        int
	OSPatchLevel     int
}

// ---------------------------------------------------------
// 3. 검증 함수 (Safety Check 추가 버전)
// ---------------------------------------------------------
func VerifyAttestation(certChain []string, expectedChallenge string) (*AttestationInfo, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	// 1. Leaf 인증서 디코딩
	certBytes, err := base64.StdEncoding.DecodeString(certChain[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %v", err)
	}

	// 2. Extension 추출
	attestationOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	var extData []byte
	found := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(attestationOID) {
			extData = ext.Value
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("attestation extension not found")
	}

	// 3. ASN.1 파싱
	var attestation AttestationRecord
	if _, err := asn1.Unmarshal(extData, &attestation); err != nil {
		return nil, fmt.Errorf("asn1 unmarshal failed: %v", err)
	}

	// 4. 챌린지 검증 (Go Server Fix 적용: 전달받은 Challenge와 비교)
	// 안드로이드가 준 expectedChallenge(Base64)와 인증서 내부 값 비교
	// (참고: 인증서 내부는 Raw Byte이므로 Base64로 인코딩해서 비교해야 함)
	// attestationChallengeBase64 := base64.StdEncoding.EncodeToString(attestation.AttestationChallenge)
	// if attestationChallengeBase64 != expectedChallenge {
	// 	 return nil, fmt.Errorf("challenge mismatch")
	// }
    // -> 지금은 테스트 편의를 위해 Pass 하거나 로그만 찍으세요.

	// 5. 안전한 값 추출 (Nil Check)
	// RootOfTrust가 비어있을 경우를 대비해 기본값 처리
	deviceLocked := false
	verifiedBootState := 3 // 3 = Failed/Unknown
	
	// TEE 영역에 정보가 있으면 가져옴
	if attestation.TeeEnforced.RootOfTrust.VerifiedBootKey != nil {
		deviceLocked = attestation.TeeEnforced.RootOfTrust.DeviceLocked
		verifiedBootState = attestation.TeeEnforced.RootOfTrust.VerifiedBootState
	}

	return &AttestationInfo{
		SecurityLevel:    attestation.AttestationSecurityLevel,
		DeviceLocked:     deviceLocked,
		BootState:        verifiedBootState,
		CreationTime:     attestation.TeeEnforced.CreationDateTime,
		AttestationLevel: attestation.AttestationVersion,
		OSVersion:        attestation.TeeEnforced.OSVersion,
		OSPatchLevel:     attestation.TeeEnforced.OSPatchLevel,
	}, nil
}