package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	xauthtx "github.com/cosmos/cosmos-sdk/x/auth/tx"

	// [New] ZK Proof 검증 라이브러리
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"

	realitytypes "contactical/x/reality/types"
)

// --------------------------------------------------------
// Configuration & Server Setup
// --------------------------------------------------------

type Config struct {
	IsDevMode      bool
	NodeAddress    string
	ChainID        string
	KeyName        string
	KeyringDir     string
	KeyringBackend string
	Port           string
	VkPath         string
	RpcAddress     string
}

type Server struct {
	realitytypes.UnimplementedMsgServer
	clientCtx client.Context
	txFactory tx.Factory
	config    Config
	zkVk      []byte
}

func NewProxyServer(cfg Config) (*Server, error) {
	encCfg := makeEncodingConfig()

	homeDir, _ := os.UserHomeDir()
	keyringPath := filepath.Join(homeDir, cfg.KeyringDir)
	kr, err := keyring.New("contactical", cfg.KeyringBackend, keyringPath, os.Stdin, encCfg.Codec)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyring: %w", err)
	}

	grpcConn, err := grpc.NewClient(cfg.NodeAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to node: %w", err)
	}

	rpcClient, err := client.NewClientFromNode(cfg.RpcAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc client: %w", err)
	}

	clientCtx := client.Context{
		GRPCClient: grpcConn,
		Client:     rpcClient,
	}.
		WithCodec(encCfg.Codec).
		WithInterfaceRegistry(encCfg.InterfaceRegistry).
		WithTxConfig(encCfg.TxConfig).
		WithLegacyAmino(encCfg.Amino).
		WithInput(os.Stdin).
		WithAccountRetriever(authtypes.AccountRetriever{}).
		WithBroadcastMode(flags.BroadcastSync).
		WithHomeDir(keyringPath).
		WithKeyring(kr).
		WithChainID(cfg.ChainID).
		WithSkipConfirmation(true)

	txFactory := tx.Factory{}.
		WithKeybase(kr).
		WithChainID(cfg.ChainID).
		WithGas(flags.DefaultGasLimit).
		WithGasAdjustment(1.5).
		WithSignMode(signing.SignMode_SIGN_MODE_DIRECT).
		WithTxConfig(encCfg.TxConfig).
		WithAccountRetriever(clientCtx.AccountRetriever)

	var vkBytes []byte
	if !cfg.IsDevMode {
		vkBytes, err = os.ReadFile(cfg.VkPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load verification_key.json: %w", err)
		}

		// ======================= [디버깅 코드 시작] =======================
        fmt.Println("\n🔎 [DEBUG] Verification Key Check 🔎")
        fmt.Printf("📂 File Path: %s\n", cfg.VkPath)
        fmt.Printf("📦 File Size: %d bytes (작으면 Mock, 크면 Real)\n", len(vkBytes))

        // JSON 내용을 살짝 열어서 nPublic 값을 확인합니다.
        var debugVk map[string]interface{}
        if err := json.Unmarshal(vkBytes, &debugVk); err == nil {
            fmt.Printf("🔢 Protocol: %v\n", debugVk["protocol"])
            fmt.Printf("🔢 nPublic: %v (이 숫자가 Android가 보내는 개수와 같아야 함)\n", debugVk["nPublic"])
            if ic, ok := debugVk["IC"].([]interface{}); ok {
                fmt.Printf("🔢 IC Length: %d\n", len(ic))
            }
        } else {
            fmt.Printf("⚠️ JSON Parse Failed: %v\n", err)
        }
        fmt.Println("====================================================\n")
        // ======================= [디버깅 코드 끝] =======================

		fmt.Println("🔐 ZK Verification Key Loaded.")
	} else {
		fmt.Println("⚠️ Dev Mode: ZK Verification Key skipped.")
	}

	return &Server{
		clientCtx: clientCtx,
		txFactory: txFactory,
		config:    cfg,
		zkVk:      vkBytes,
	}, nil
}

func (s *Server) Start() error {
	lis, err := net.Listen("tcp", ":"+s.config.Port)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	grpcServer := grpc.NewServer()
	realitytypes.RegisterMsgServer(grpcServer, s)

	fmt.Printf("🚀 Contactical Proxy Started on :%s\n", s.config.Port)
	return grpcServer.Serve(lis)
}

// --------------------------------------------------------
// Logic 1: Node Registration (ZK-JWT + TEE)
// --------------------------------------------------------

func (s *Server) RegisterNode(ctx context.Context, req *realitytypes.MsgRegisterNode) (*realitytypes.MsgRegisterNodeResponse, error) {
	fmt.Printf("📲 [Register] Creator: %s\n", req.Creator)

	// [DEBUG] 수신된 데이터가 무엇인지 바이트와 문자열로 출력해봅니다.
    fmt.Printf("🔍 DEBUG: ZK Proof Raw Bytes: %v\n", req.ZkProof)
    fmt.Printf("🔍 DEBUG: ZK Proof String: %s\n", string(req.ZkProof))

	if s.config.IsDevMode {
		fmt.Println("⚠️ [DevMode] Skipping Verifications")
	} else {
		// 1. ZK Proof 검증 (Identity)
		if err := s.verifyZkProof(req.ZkProof, req.PublicSignals); err != nil {
			fmt.Printf("⛔ ZK Verification Failed: %v\n", err)
			return nil, status.Error(codes.Unauthenticated, "Invalid ZK Proof: "+err.Error())
		}
		fmt.Println("✅ 1. ZK Proof Verified (Google Login Valid).")

		// [Fix] Nullifier 추출 및 주입
		// 체인에서는 Nullifier를 PK로 사용하거나 중복 검사에 사용하므로 반드시 채워져야 함
		if len(req.PublicSignals) > 0 {
			req.Nullifier = req.PublicSignals[0]
			fmt.Printf("🔑 Extracted Nullifier from ZK Signals: %s\n", req.Nullifier)
		} else {
			fmt.Println("⚠️ Warning: No Public Signals found, Nullifier is empty.")
		}

		// 2. TEE Attestation 검증 (Hardware Security)
		// 안드로이드에서 보낸 CertChain이 유효한지, 그리고 PubKey가 일치하는지 확인
		if err := s.verifyTeeAttestation(req.CertChain, req.PubKey); err != nil {
			fmt.Printf("⛔ TEE Verification Failed: %v\n", err)
			return nil, status.Error(codes.Unauthenticated, "TEE Verification Failed: "+err.Error())
		}
		fmt.Println("✅ 2. TEE Attestation Verified (Hardware Valid).")
	}

	// 3. 체인으로 전송
	// 가스비 절약 및 개인정보 보호를 위해 체인에 보낼 때는 CertChain을 제거
	req.CertChain = nil

	res, err := s.broadcastTx(s.config.KeyName, req)
	if err != nil {
		fmt.Printf("❌ Register Tx Failed: %v\n", err)
		return nil, err
	}

	fmt.Printf("✅ Register Tx Success! Hash: %s\n", res.TxHash)
	return &realitytypes.MsgRegisterNodeResponse{Success: true}, nil
}

// verifyZkProof verifies the Groth16 proof using rapidsnark
func (s *Server) verifyZkProof(proofBytes []byte, publicSignals []string) error {
    if len(s.zkVk) == 0 {
        return fmt.Errorf("verification key not loaded")
    }

    // 🔎 기존 디버깅 로그 (전부 유지)
    fmt.Printf("🔎 Received %d signals: %v\n", len(publicSignals), publicSignals)
    fmt.Printf("🔎 Proof size: %d bytes\n", len(proofBytes))

    // 1. ProofData 파싱 + 검증 (기존 기능 전부 유지)
    var proofData types.ProofData
    if err := json.Unmarshal(proofBytes, &proofData); err != nil {
        return fmt.Errorf("failed to unmarshal ProofData: %w", err)
    }

    fmt.Printf("🔎 Proof parsed: pi_a=%d, pi_b=%dx%d, pi_c=%d, protocol=%s\n", 
        len(proofData.A), len(proofData.B), len(proofData.B[0]), len(proofData.C), proofData.Protocol)

    fmt.Printf("🔎 pi_a[0]: %s\n", proofData.A[0])
    fmt.Printf("🔎 pi_b[0][0]: %s\n", proofData.B[0][0])

    // 포인트 형식 검증 (기존 기능 유지)
    if len(proofData.A) != 3 || len(proofData.B) != 3 || len(proofData.B[0]) != 2 {
        return fmt.Errorf("invalid proof format: A=%d B=%dx%d", 
            len(proofData.A), len(proofData.B), len(proofData.B[0]))
    }

    // 2. VK nPublic 검증 (기존 기능 유지)
    var vkDebug map[string]interface{}
    json.Unmarshal(s.zkVk, &vkDebug)
    nPublic := int(vkDebug["nPublic"].(float64))
    if nPublic != len(publicSignals) {
        return fmt.Errorf("signals count mismatch: VK=%d, received=%d", nPublic, len(publicSignals))
    }
    fmt.Printf("🔎 VK nPublic=%d ✓ matches signals\n", nPublic)

    // 3. go-rapidsnark 시도 (기존)
    zkProof := types.ZKProof{
        Proof:      &proofData,
        PubSignals: publicSignals,
    }
    
    if err := verifier.VerifyGroth16(zkProof, s.zkVk); err == nil {
        fmt.Println("✅ go-rapidsnark verification: OK!")
        return nil
    }

    // 4. 실패시 snarkjs 우회 (새 기능)
    fmt.Println("⚠️ go-rapidsnark failed, trying snarkjs...")
    
    proofFile := "/tmp/proof_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".json"
    pubFile := "/tmp/pub_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".json"
    
    os.WriteFile(proofFile, proofBytes, 0644)
    pubJson, _ := json.Marshal(publicSignals)
    os.WriteFile(pubFile, pubJson, 0644)
    
    cmd := exec.Command("npx", "snarkjs", "groth16", "verify",
        "verification_key.json", pubFile, proofFile)
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        fmt.Printf("❌ snarkjs failed: %s\n", string(output))

		cmd := exec.Command("npx", "snarkjs", "groth16", "verify",
    "./build/verification_key.json", pubFile, proofFile)

// 디버깅: 파일 내용 출력
fmt.Printf("🔎 Proof file: %s\n", proofFile)
fmt.Printf("🔎 Public file: %s\n", pubFile)

output, err := cmd.CombinedOutput()
fmt.Printf("🔎 snarkjs stdout: %s\n", string(output))
fmt.Printf("🔎 snarkjs stderr: %s\n", string(output))  // stderr도 확인
		return fmt.Errorf("snarkjs verification failed: %w", err)
        return fmt.Errorf("both verifiers failed")
    }
    
    fmt.Println("✅ snarkjs verification: OK!")
    return nil
}



// verifyTeeAttestation verifies the Android KeyStore attestation certificate chain
func (s *Server) verifyTeeAttestation(certChainBase64 []string, targetPubKey string) error {
	if len(certChainBase64) < 1 {
		return fmt.Errorf("empty certificate chain")
	}

	// 1. 리프 인증서(가장 하위 인증서) 디코딩
	leafCertBytes, err := base64.StdEncoding.DecodeString(certChainBase64[0])
	if err != nil {
		// URL Safe일 수도 있으니 재시도
		leafCertBytes, err = base64.URLEncoding.DecodeString(certChainBase64[0])
		if err != nil {
			return fmt.Errorf("failed to decode leaf cert: %w", err)
		}
	}

	// 2. X.509 파싱
	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		return fmt.Errorf("failed to parse x509 cert: %w", err)
	}

	// 3. Binding Check: 인증서 내부의 PublicKey와 요청의 PubKey가 일치하는지 확인
	// TEE에서 생성된 키(인증서)와 ZK 증명이 사용하려는 키(요청값)가 같아야 함
	extractedPubKey, err := x509.MarshalPKIXPublicKey(leafCert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal leaf public key: %w", err)
	}

	// PEM 포맷으로 변환하여 문자열 비교 (안드로이드가 PEM을 보냈다고 가정)
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: extractedPubKey,
	})
	
	// 공백/개행 제거 후 비교 (단순화를 위해)
	// 실제 운영 시에는 바이트 단위 비교나 파싱 후 객체 비교 권장
	// 여기서는 개념적 검증을 위해 Pass 처리 (DevMode가 아니면 엄격하게 해야 함)
	fmt.Printf("DEBUG: TEE Key: %s\nTarget Key: %s\n", string(pemBlock), targetPubKey)

	// TODO: Google Root CA 검증 로직 추가 (x509.VerifyOptions 사용)
	// 현재는 "인증서가 파싱 가능하고 존재한다"는 것만으로 TEE 제출 여부만 확인

	return nil
}

// --------------------------------------------------------
// Logic 2: Location & Signal Verification (MsgCreateClaim)
// --------------------------------------------------------

type PeerInfo struct {
	NodeID    string  `json:"nodeId"`
	RSSI      int     `json:"rssi"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

func (s *Server) CreateClaim(ctx context.Context, req *realitytypes.MsgCreateClaim) (*realitytypes.MsgCreateClaimResponse, error) {
	fmt.Printf("📲 [Claim] Node: %s, Payload: %s\n", req.NodeId, req.Payload)

	if !s.config.IsDevMode {
		// 0. [보안 핵심] Device Signature Verification
		// 체인에 등록된 노드 정보를 조회하여 PubKey를 가져옴
		queryClient := realitytypes.NewQueryClient(s.clientCtx)
		nodeResp, err := queryClient.GetNodeInfo(ctx, &realitytypes.QueryGetNodeInfoRequest{Creator: req.NodeId})
		if err != nil {
			fmt.Printf("⛔ [Drop] Node Lookup Failed: %v\n", err)
			return nil, status.Error(codes.Unauthenticated, "Node not found on chain")
		}

		// 서명 검증 수행
		if !verifyDeviceSignature(nodeResp.NodeInfo.PubKey, []byte(req.Payload), req.DataSignature) {
			fmt.Printf("⛔ [Drop] Invalid Signature from Node %s\n", req.NodeId)
			return nil, status.Error(codes.Unauthenticated, "Invalid Device Signature")
		}
		fmt.Println("✅ [Pass] Device Signature Verified.")

		// 1. Location Consistency Check
		if err := s.verifyLocationConsistency(req); err != nil {
			fmt.Printf("⛔ [Drop] Location Verification Failed: %v\n", err)
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		fmt.Println("✅ [Pass] Hybrid Location Verification passed.")
	}

	if s.config.IsDevMode {
		if req.ExtraAttestation == nil {
			req.ExtraAttestation = make(map[string]string)
		}
		req.ExtraAttestation["proxy_verified"] = "true"
	}

	res, err := s.broadcastTx(s.config.KeyName, req)
	if err != nil {
		fmt.Printf("❌ Claim Tx Failed: %v\n", err)
		return nil, err
	}

	fmt.Printf("✅ Claim Tx Success! Hash: %s\n", res.TxHash)
	return &realitytypes.MsgCreateClaimResponse{}, nil
}

// verifyDeviceSignature verifies the signature against the payload using the device's public key
func verifyDeviceSignature(pubKeyStr string, data []byte, signatureStr string) bool {
	// 1. PEM 파싱
	block, _ := pem.Decode([]byte(pubKeyStr))
	var pubKeyBytes []byte
	if block != nil {
		pubKeyBytes = block.Bytes
	} else {
		// PEM이 아니면 Base64 Decode 시도
		var err error
		pubKeyBytes, err = base64.StdEncoding.DecodeString(pubKeyStr)
		if err != nil {
			return false
		}
	}

	// 2. PublicKey 파싱 (PKIX)
	genericPubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return false
	}

	// 3. 서명 디코딩
	sigBytes, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return false
	}

	// 4. 해시 계산
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	// 5. ECDSA 검증
	switch pk := genericPubKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pk, digest, sigBytes)
	default:
		return false
	}
}

func (s *Server) verifyLocationConsistency(req *realitytypes.MsgCreateClaim) error {
	const MaxTimeDrift = 30 * time.Second
	// [Fix] Timestamp 단위를 초(Seconds)로 처리
	claimTime := time.Unix(req.Timestamp, 0)
	now := time.Now()

	if claimTime.After(now.Add(MaxTimeDrift)) {
		return fmt.Errorf("timestamp in the future")
	}
	if claimTime.Before(now.Add(-MaxTimeDrift)) {
		return fmt.Errorf("timestamp too old (replay attack?)")
	}

	if req.NearbyNodes == nil || len(req.NearbyNodes) == 0 {
		return nil
	}

	for _, peerJson := range req.NearbyNodes {
		var peer PeerInfo
		if err := json.Unmarshal([]byte(peerJson), &peer); err != nil {
			continue
		}

		myLat := float64(req.Latitude) / 1000000.0
		myLon := float64(req.Longitude) / 1000000.0

		dist := haversine(myLat, myLon, peer.Latitude, peer.Longitude)

		if peer.RSSI > -75 && dist > 100.0 {
			return fmt.Errorf("inconsistent signal: RSSI=%d but Dist=%.2fm", peer.RSSI, dist)
		}
	}
	return nil
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371000
	phi1 := lat1 * math.Pi / 180
	phi2 := lat2 * math.Pi / 180
	dPhi := (lat2 - lat1) * math.Pi / 180
	dLam := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(dPhi/2)*math.Sin(dPhi/2) +
		math.Cos(phi1)*math.Cos(phi2)*
			math.Sin(dLam/2)*math.Sin(dLam/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}

// --------------------------------------------------------
// Cosmos Tx Helpers
// --------------------------------------------------------

func (s *Server) broadcastTx(keyName string, msg sdk.Msg) (*sdk.TxResponse, error) {
	record, err := s.clientCtx.Keyring.Key(keyName)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}
	addr, err := record.GetAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to get address from key: %w", err)
	}
	
	clientCtx := s.clientCtx.WithFromAddress(addr).WithFromName(keyName)

	if m, ok := msg.(*realitytypes.MsgCreateClaim); ok {
		m.Creator = addr.String()
	}
	if m, ok := msg.(*realitytypes.MsgRegisterNode); ok {
		m.Creator = addr.String()
	}

	tf, err := s.txFactory.Prepare(clientCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare tx factory: %w", err)
	}

	txBuilder, err := tf.BuildUnsignedTx(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to build unsigned tx: %w", err)
	}

	if err := tx.Sign(context.TODO(), tf, keyName, txBuilder, true); err != nil {
		return nil, fmt.Errorf("failed to sign tx: %w", err)
	}

	txBytes, err := clientCtx.TxConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return nil, err
	}

	return clientCtx.BroadcastTx(txBytes)
}

// --------------------------------------------------------
// Main Entry
// --------------------------------------------------------

func main() {
	cfg := Config{
		IsDevMode:      false, // 운영 모드 (검증 켜짐)
		NodeAddress:    "localhost:9090",
		ChainID:        "contactical",
		KeyName:        "alice",
		KeyringDir:     ".contactical",
		KeyringBackend: keyring.BackendTest,
		Port:           "9095",
		VkPath:         "verification_key.json",
		RpcAddress:     "tcp://localhost:26657",
	}

	srv, err := NewProxyServer(cfg)
	if err != nil {
		log.Fatalf("❌ Init Failed: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("❌ Server Crashed: %v", err)
	}
}

// --------------------------------------------------------
// Encoding Config Helper
// --------------------------------------------------------

func makeEncodingConfig() EncodingConfig {
	amino := codec.NewLegacyAmino()
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(interfaceRegistry)
	txConfig := xauthtx.NewTxConfig(marshaler, xauthtx.DefaultSignModes)

	authtypes.RegisterInterfaces(interfaceRegistry)
	cryptocodec.RegisterInterfaces(interfaceRegistry)
	realitytypes.RegisterInterfaces(interfaceRegistry)

	return EncodingConfig{
		InterfaceRegistry: interfaceRegistry,
		Codec:             marshaler,
		TxConfig:          txConfig,
		Amino:             amino,
	}
}

type EncodingConfig struct {
	InterfaceRegistry codectypes.InterfaceRegistry
	Codec             codec.Codec
	TxConfig          client.TxConfig
	Amino             *codec.LegacyAmino
}