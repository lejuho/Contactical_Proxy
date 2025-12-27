pragma circom 2.0.0;

template JwtVerifier() {
    signal input jwt_valid;
    signal input device_tier;
    
    signal output valid_device;
    
    // device_tier가 0~1 범위라고 가정하고 곱셈만 사용
    valid_device <== jwt_valid * device_tier;
}

component main {public [jwt_valid]} = JwtVerifier();
