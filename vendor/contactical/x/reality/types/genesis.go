package types

import "fmt"

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Params:        DefaultParams(),
		ClaimList:     []Claim{},
		NodeList:      []NodeInfo{},
		NullifierList: []string{},
	}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	claimIdMap := make(map[uint64]bool)
	claimCount := gs.GetClaimCount()
	for _, elem := range gs.ClaimList {
		if _, ok := claimIdMap[elem.Id]; ok {
			return fmt.Errorf("duplicated id for claim")
		}
		if elem.Id >= claimCount {
			return fmt.Errorf("claim id should be lower or equal than the last id")
		}
		claimIdMap[elem.Id] = true
	}

	// Validate NodeList
	nodeCreatorMap := make(map[string]bool)
	for _, elem := range gs.NodeList {
		if _, ok := nodeCreatorMap[elem.Creator]; ok {
			return fmt.Errorf("duplicated creator in node list")
		}
		nodeCreatorMap[elem.Creator] = true
	}

	// Validate NullifierList
	nullifierMap := make(map[string]bool)
	for _, nullifier := range gs.NullifierList {
		if _, ok := nullifierMap[nullifier]; ok {
			return fmt.Errorf("duplicated nullifier")
		}
		nullifierMap[nullifier] = true
	}

	return gs.Params.Validate()
}
