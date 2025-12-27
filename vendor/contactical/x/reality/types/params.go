package types

import "fmt"

// NewParams creates a new Params instance with default values.
func NewParams() Params {
	return Params{
		RewardBaseUnit:    1000,
		MaxTrustScore:     100,
		MinScoreThreshold: 10,
		SecurityWeights: map[string]int32{
			"strongbox":        50,
			"tee":              30,
			"boot_lock":        10,
			"density_per_node": 20,
		},
	}
}

// DefaultParams returns a default set of parameters.
func DefaultParams() Params {
	return NewParams()
}

// Validate validates the set of params.
func (p Params) Validate() error {
	if p.RewardBaseUnit <= 0 {
		return fmt.Errorf("reward base unit must be positive: %d", p.RewardBaseUnit)
	}
	if p.MaxTrustScore <= 0 {
		return fmt.Errorf("max trust score must be positive: %d", p.MaxTrustScore)
	}
	if p.MinScoreThreshold < 0 {
		return fmt.Errorf("min score threshold must be non-negative: %d", p.MinScoreThreshold)
	}
	if p.MaxTrustScore < p.MinScoreThreshold {
		return fmt.Errorf("max trust score (%d) cannot be less than min score threshold (%d)", p.MaxTrustScore, p.MinScoreThreshold)
	}

	if p.SecurityWeights == nil {
		return fmt.Errorf("security weights cannot be nil")
	}
	for k, v := range p.SecurityWeights {
		if v < 0 {
			return fmt.Errorf("security weight for %s must be non-negative: %d", k, v)
		}
	}

	return nil
}