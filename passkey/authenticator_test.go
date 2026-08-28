package passkey_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// virtualAuthenticator is a software authenticator: it holds an ES256 key
// and produces the attestation and assertion responses a real one would.
//
// Testing WebAuthn without one is testing nothing. The properties worth
// checking here — that a counter regression is caught, that an assertion
// without user verification is refused, that a user handle cannot name
// somebody else's account — are all downstream of a signature actually
// verifying, so the fake has to sign for real.
type virtualAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	aaguid       []byte
	// signCount is what the authenticator reports and increments. Tests
	// drive it backwards to simulate a cloned device.
	signCount uint32
	// userVerified controls the UV flag.
	userVerified bool
}

func newAuthenticator(t *testing.T) *virtualAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return &virtualAuthenticator{
		key: key, credentialID: credID, aaguid: make([]byte, 16),
		signCount: 1, userVerified: true,
	}
}

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagBackupElig   = 0x08
	flagBackupState  = 0x10
	flagAttestedData = 0x40
)

func (a *virtualAuthenticator) flags(attested bool) byte {
	f := byte(flagUserPresent | flagBackupElig | flagBackupState)
	if a.userVerified {
		f |= flagUserVerified
	}
	if attested {
		f |= flagAttestedData
	}
	return f
}

// coseKey encodes the public key in the COSE_Key form WebAuthn expects.
func (a *virtualAuthenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	// 1: kty=EC2(2), 3: alg=ES256(-7), -1: crv=P-256(1), -2: x, -3: y
	key := map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}
	enc, err := cbor.Marshal(key)
	if err != nil {
		t.Fatalf("cbor.Marshal(cose key): %v", err)
	}
	return enc
}

func (a *virtualAuthenticator) authData(t *testing.T, rpID string, attested bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))
	var buf bytes.Buffer
	buf.Write(rpIDHash[:])
	buf.WriteByte(a.flags(attested))
	_ = binary.Write(&buf, binary.BigEndian, a.signCount)
	if attested {
		buf.Write(a.aaguid)
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(a.credentialID)))
		buf.Write(a.credentialID)
		buf.Write(a.coseKey(t))
	}
	return buf.Bytes()
}

func clientData(t *testing.T, ceremonyType, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type": ceremonyType, "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// register produces the response to navigator.credentials.create().
func (a *virtualAuthenticator) register(t *testing.T, challenge, rpID, origin string) *http.Request {
	t.Helper()
	cd := clientData(t, "webauthn.create", challenge, origin)
	attObj, err := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(t, rpID, true),
	})
	if err != nil {
		t.Fatalf("cbor.Marshal(attestationObject): %v", err)
	}
	return postJSON(t, map[string]any{
		"id": b64(a.credentialID), "rawId": b64(a.credentialID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64(cd), "attestationObject": b64(attObj),
			"transports": []string{"internal"},
		},
	})
}

// assert produces the response to navigator.credentials.get(), signing for
// real so the verification under test is a real verification.
func (a *virtualAuthenticator) assert(t *testing.T, challenge, rpID, origin, userHandle string) *http.Request {
	t.Helper()
	cd := clientData(t, "webauthn.get", challenge, origin)
	authData := a.authData(t, rpID, false)

	cdHash := sha256.Sum256(cd)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}

	resp := map[string]any{
		"clientDataJSON": b64(cd), "authenticatorData": b64(authData), "signature": b64(sig),
	}
	if userHandle != "" {
		resp["userHandle"] = b64([]byte(userHandle))
	}
	return postJSON(t, map[string]any{
		"id": b64(a.credentialID), "rawId": b64(a.credentialID), "type": "public-key",
		"response": resp,
	})
}

func postJSON(t *testing.T, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// challengeFrom pulls the challenge out of the options authit produced, the
// way the browser would.
func challengeFrom(t *testing.T, options []byte) string {
	t.Helper()
	var envelope struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &envelope); err != nil {
		t.Fatalf("decoding ceremony options: %v", err)
	}
	if envelope.PublicKey.Challenge == "" {
		t.Fatalf("no challenge in options: %s", options)
	}
	return envelope.PublicKey.Challenge
}
