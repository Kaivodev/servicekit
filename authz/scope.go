package authz

import (
	"bytes"
	"encoding/json"
	"io"
)

// Scope types carried in acting_scope.type (aipay.common.v1.ScopeType, account
// model decisions A83 and A84).
const (
	ScopePlatform    = "platform"
	ScopeAccount     = "account"
	ScopeBusiness    = "business"
	ScopeApplication = "application"
)

// Account types carried in acting_scope.account_type.
const (
	AccountPersonal     = "personal"
	AccountOrganization = "organization"
)

// Scope is the acting_scope claim:
//
//	platform:    no IDs, or one target account IAM bound the operation to
//	account:     account_id, account_type
//	business:    account_id, account_type, business_id
//	application: account_id, account_type, business_id, application_id
//
// org_id is optional for organization accounts and forbidden for personal
// accounts. Members other than these, such as the superseded
// organization_id, reject the assertion.
type Scope struct {
	Type          string `json:"type"`
	AccountID     string `json:"account_id,omitempty"`
	AccountType   string `json:"account_type,omitempty"`
	OrgID         string `json:"org_id,omitempty"`
	BusinessID    string `json:"business_id,omitempty"`
	ApplicationID string `json:"application_id,omitempty"`
}

func (s *Scope) UnmarshalJSON(data []byte) error {
	type plain Scope
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return errMalformed
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errMalformed
	}
	*s = Scope(value)
	return nil
}

func (s Scope) valid() bool {
	var account bool
	switch s.AccountType {
	case AccountPersonal:
		// A personal account never carries an organization.
		account = idPattern.MatchString(s.AccountID) && s.OrgID == ""
	case AccountOrganization:
		account = idPattern.MatchString(s.AccountID) && (s.OrgID == "" || idPattern.MatchString(s.OrgID))
	}
	unbound := s.AccountID == "" && s.AccountType == "" && s.OrgID == ""
	switch s.Type {
	case ScopePlatform:
		return (unbound || account) && s.BusinessID == "" && s.ApplicationID == ""
	case ScopeAccount:
		return account && s.BusinessID == "" && s.ApplicationID == ""
	case ScopeBusiness:
		return account && idPattern.MatchString(s.BusinessID) && s.ApplicationID == ""
	case ScopeApplication:
		return account && idPattern.MatchString(s.BusinessID) && idPattern.MatchString(s.ApplicationID)
	}
	return false
}

// Account is the funds account a call is bound to. Funds always belong to an
// account, never to a business or application.
type Account struct {
	ID   string
	Type string
	// OrgID is set only for organization accounts when IAM supplied it.
	OrgID string
}

// Account returns the account of the scope, if it names one.
func (s Scope) Account() (Account, bool) {
	if s.AccountID == "" {
		return Account{}, false
	}
	return Account{ID: s.AccountID, Type: s.AccountType, OrgID: s.OrgID}, true
}
