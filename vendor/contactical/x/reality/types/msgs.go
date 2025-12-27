// x/reality/types/msgs.go
package types

import (
	"fmt"
	"regexp"
)

func (msg MsgCreateClaim) ValidateBasic() error {
	if msg.SensorHash == "" {
		return fmt.Errorf("sensor hash cannot be empty")
	}
	if len(msg.GnssHash) != 64 {
		return fmt.Errorf("invalid gnss hash length: expected 64, got %d", len(msg.GnssHash))
	}
	isHex := regexp.MustCompile(`^[a-fA-F0-9]+$`).MatchString
	if !isHex(msg.GnssHash) {
		return fmt.Errorf("invalid gnss hash format: must be hex string")
	}
	// AnchorSignature 필수 체크 삭제
	// if msg.AnchorSignature == "" {
	//     return fmt.Errorf("anchor signature cannot be empty")
	// }
	return nil
}
