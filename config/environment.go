package config

import "errors"

// Environment gates development-only components such as the in-memory signer.
type Environment string

const (
	Production  Environment = "production"
	Staging     Environment = "staging"
	Development Environment = "development"
)

// LoadEnvironment reads AIPAY_ENVIRONMENT. An unset value means production, so
// a missing setting can never enable a development-only component.
func LoadEnvironment(get func(string) string) (Environment, error) {
	if get == nil {
		return "", errors.New("environment requires a reader")
	}
	switch value := Environment(get("AIPAY_ENVIRONMENT")); value {
	case "":
		return Production, nil
	case Production, Staging, Development:
		return value, nil
	default:
		return "", errors.New("AIPAY_ENVIRONMENT must be production, staging or development")
	}
}
