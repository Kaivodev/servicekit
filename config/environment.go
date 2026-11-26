package config

import "errors"

// Environment controls access to development features. Services should use
// IsDevelopment or IsDevelopmentOrTest for these checks. Both methods treat
// the zero value and unrecognized values as production.
type Environment string

// EnvironmentVariable names the process setting read by LoadEnvironment.
const EnvironmentVariable = "AIPAY_ENVIRONMENT"

const (
	Development Environment = "development"
	Test        Environment = "test"
	Production  Environment = "production"

	// Deprecated: A130 removed Staging. ParseEnvironment rejects it and both
	// environment predicates treat it as production. Remove after services migrate.
	Staging Environment = "staging"
)

// ParseEnvironment accepts the exact values development, test and production.
// An empty value defaults to production.
func ParseEnvironment(value string) (Environment, error) {
	switch env := Environment(value); env {
	case "":
		return Production, nil
	case Development, Test, Production:
		return env, nil
	case Staging:
		return "", errors.New("AIPAY_ENVIRONMENT no longer accepts staging (A130): use development for the Kubernetes staging cluster, or production")
	default:
		return "", errors.New("AIPAY_ENVIRONMENT must be development, test or production")
	}
}

// LoadEnvironment reads AIPAY_ENVIRONMENT through get and parses its value.
func LoadEnvironment(get func(string) string) (Environment, error) {
	if get == nil {
		return "", errors.New("environment requires a reader")
	}
	return ParseEnvironment(get(EnvironmentVariable))
}

// IsDevelopment permits development-only features such as *_TEST_ONLY_ALLOW_PRIVATE
// overrides, memory and file signers, local sealers and development keyrings.
func (e Environment) IsDevelopment() bool {
	return e == Development
}

// IsDevelopmentOrTest permits file data sources, loopback or HTTP calls to
// local emulators, and local plaintext Redis in development and test.
func (e Environment) IsDevelopmentOrTest() bool {
	return e == Development || e == Test
}
