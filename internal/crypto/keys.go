package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/netip"
)

type Keys struct {
	oauth           [32]byte
	transcript      [32]byte
	billing         [32]byte
	identity        [32]byte
	webSession      [32]byte
	adminAuthSource [32]byte
}

func DeriveKeys(master []byte) (Keys, error) {
	if len(master) != 32 {
		return Keys{}, fmt.Errorf("master key must be 32 bytes")
	}
	derive := func(info string) ([32]byte, error) {
		var key [32]byte
		value, err := hkdf.Key(sha256.New, master, []byte("supergrok-api/v1"), info, len(key))
		if err != nil {
			return key, err
		}
		copy(key[:], value)
		return key, nil
	}
	var keys Keys
	var err error
	if keys.oauth, err = derive("oauth-credentials"); err != nil {
		return Keys{}, err
	}
	if keys.transcript, err = derive("responses-transcript"); err != nil {
		return Keys{}, err
	}
	if keys.billing, err = derive("billing-raw-snapshot"); err != nil {
		return Keys{}, err
	}
	if keys.identity, err = derive("identity-fingerprint"); err != nil {
		return Keys{}, err
	}
	if keys.webSession, err = derive("web-session-signing"); err != nil {
		return Keys{}, err
	}
	if keys.adminAuthSource, err = derive("admin-auth-source-hmac"); err != nil {
		return Keys{}, err
	}
	return keys, nil
}

func (k Keys) OAuth() [32]byte      { return k.oauth }
func (k Keys) Transcript() [32]byte { return k.transcript }
func (k Keys) Billing() [32]byte    { return k.billing }
func (k Keys) WebSession() [32]byte { return k.webSession }
func (k Keys) AdminAuthSourceFingerprint(address netip.Addr) [32]byte {
	address = address.Unmap()
	mac := hmac.New(sha256.New, k.adminAuthSource[:])
	mac.Write([]byte("admin-auth-source/v1\x00"))
	if address.Is4() {
		value := address.As4()
		mac.Write([]byte{4})
		mac.Write(value[:])
	} else {
		value := address.As16()
		mac.Write([]byte{6})
		mac.Write(value[:])
	}
	var fingerprint [32]byte
	copy(fingerprint[:], mac.Sum(nil))
	return fingerprint
}
func (k Keys) IdentityFingerprint(issuer, subject string) [32]byte {
	mac := hmac.New(sha256.New, k.identity[:])
	mac.Write([]byte(issuer))
	mac.Write([]byte{0})
	mac.Write([]byte(subject))
	var fingerprint [32]byte
	copy(fingerprint[:], mac.Sum(nil))
	return fingerprint
}
