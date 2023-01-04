package ecies

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"testing"
)

var flDump = flag.Bool("dump", false, "write encrypted test message to file")

func dumpEnc(out []byte) {
	if *flDump {
		f, _ := os.OpenFile("test.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()
		_, _ = f.Write(out)
		_, _ = f.Write([]byte("\n"))
	}
}

func curveFromName(name string) elliptic.Curve {
	for curve := range paramsFromCurve {
		if curve.Params().Name == name {
			return curve
		}
	}
	return nil
}

func bigIntToStr(i *big.Int) string {
	return i.Text(62)
}

func strToBigInt(s string) *big.Int {
	i, _ := new(big.Int).SetString(s, 62)
	return i
}

// Ensure the KDF generates appropriately sized keys.
func TestKDF(t *testing.T) {
	msg := []byte("Hello, world")
	h := sha256.New()

	k, err := concatKDF(h, msg, nil, 64)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	if len(k) != 64 {
		fmt.Printf("KDF: generated key is the wrong size (%d instead of 64\n",
			len(k))
		t.FailNow()
	}
}

var ErrBadSharedKeys = fmt.Errorf("ecies: shared keys don't match")

// cmpPublic returns true if the two public keys represent the same pojnt.
func cmpPublic(pub1, pub2 PublicKey) bool {
	if pub1.X == nil || pub1.Y == nil {
		fmt.Println(ErrInvalidPublicKey.Error())
		return false
	}
	if pub2.X == nil || pub2.Y == nil {
		fmt.Println(ErrInvalidPublicKey.Error())
		return false
	}
	pub1Out := elliptic.Marshal(pub1.Curve, pub1.X, pub1.Y)
	pub2Out := elliptic.Marshal(pub2.Curve, pub2.X, pub2.Y)

	return bytes.Equal(pub1Out, pub2Out)
}

// cmpPrivate returns true if the two private keys are the same.
func cmpPrivate(prv1, prv2 *PrivateKey) bool {
	if prv1 == nil || prv1.D == nil {
		return false
	} else if prv2 == nil || prv2.D == nil {
		return false
	} else if prv1.D.Cmp(prv2.D) != 0 {
		return false
	} else {
		return cmpPublic(prv1.PublicKey, prv2.PublicKey)
	}
}

// Validate the ECDH component.
func TestSharedKey(t *testing.T) {
	for c := range paramsFromCurve {
		testSharedKey(t, c)
	}
}

func testSharedKey(t *testing.T, curve elliptic.Curve) {
	name := curve.Params().Name
	prv1, err := GenerateKey(rand.Reader, curve, nil)
	if err != nil {
		fmt.Println(name, err.Error())
		t.FailNow()
	}

	prv2, err := GenerateKey(rand.Reader, curve, nil)
	if err != nil {
		fmt.Println(name, err.Error())
		t.FailNow()
	}

	sk1, err := prv1.GenerateShared(&prv2.PublicKey)
	if err != nil {
		fmt.Println(name, err.Error())
		t.FailNow()
	}

	if *flDump {
		dumpEnc([]byte(fmt.Sprintf(
			`gen-shared-1:
  Curve: %s
  Private:
    PX: "%s"
    PY: "%s"
    PD: "%s"
  Public:
    PX: "%s"
    PY: "%s"
  Shared: "%s"`,
			name,
			bigIntToStr(prv1.X),
			bigIntToStr(prv1.Y),
			bigIntToStr(prv1.D),
			bigIntToStr(prv2.X),
			bigIntToStr(prv2.Y),
			hex.EncodeToString(sk1),
		)))
	}

	sk2, err := prv2.GenerateShared(&prv1.PublicKey)
	if err != nil {
		fmt.Println(name, err.Error())
		t.FailNow()
	}

	if !bytes.Equal(sk1, sk2) {
		fmt.Println(name, ErrBadSharedKeys.Error())
		t.FailNow()
	}
}

func TestVectorSharedKey(t *testing.T) {
	var testVectors map[string]struct {
		Curve   string
		Private struct {
			PX string
			PY string
			PD string
		}
		Public struct {
			PX string
			PY string
		}
		Shared string
	}
	testData, err := os.ReadFile("test-vectors/gen-shared.json")
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	if err := json.Unmarshal(testData, &testVectors); err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	for name, vector := range testVectors {
		curve := curveFromName(vector.Curve)
		if curve == nil {
			fmt.Println(name, ErrInvalidCurve.Error())
			t.FailNow()
		}
		prv := PrivateKey{
			PublicKey: PublicKey{
				Curve: curve,
				X:     strToBigInt(vector.Private.PX),
				Y:     strToBigInt(vector.Private.PY),
			},
			D: strToBigInt(vector.Private.PD),
		}
		pub := PublicKey{
			Curve: curve,
			X:     strToBigInt(vector.Public.PX),
			Y:     strToBigInt(vector.Public.PY),
		}
		sk, _ := hex.DecodeString(vector.Shared)
		if prv.X == nil || prv.Y == nil || prv.D == nil || pub.X == nil || pub.Y == nil || sk == nil {
			fmt.Println(name, "invalid BigInt in test vector")
			t.FailNow()
		}

		skGen, err := prv.GenerateShared(&pub)
		if err != nil {
			fmt.Println(name, err.Error())
			t.FailNow()
		}
		if !bytes.Equal(sk, skGen) {
			fmt.Println(name, ErrBadSharedKeys.Error())
			t.FailNow()
		}
	}
}

// Ensure a public key can be successfully marshalled and unmarshalled, and
// that the decoded key is the same as the original.
func TestMarshalPublic(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := MarshalPublic(&prv.PublicKey)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	pub, err := UnmarshalPublic(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !cmpPublic(prv.PublicKey, *pub) {
		fmt.Println("ecies: failed to unmarshal public key")
		t.FailNow()
	}
}

// Ensure that a private key can be encoded into DER format, and that
// the resulting key is properly parsed back into a public key.
func TestMarshalPrivate(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := MarshalPrivate(prv)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	dumpEnc(out)

	prv2, err := UnmarshalPrivate(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !cmpPrivate(prv, prv2) {
		fmt.Println("ecdh: private key import failed")
		t.FailNow()
	}
}

// Ensure that a private key can be successfully encoded to PEM format, and
// the resulting key is properly parsed back in.
func TestPrivatePEM(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := ExportPrivatePEM(prv)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	dumpEnc(out)

	prv2, err := ImportPrivatePEM(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if !cmpPrivate(prv, prv2) {
		fmt.Println("ecdh: import from PEM failed")
		t.FailNow()
	}
}

// Ensure that a public key can be successfully encoded to PEM format, and
// the resulting key is properly parsed back in.
func TestPublicPEM(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := ExportPublicPEM(&prv.PublicKey)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}
	dumpEnc(out)

	pub2, err := ImportPublicPEM(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	} else if !cmpPublic(prv.PublicKey, *pub2) {
		fmt.Println("ecdh: import from PEM failed")
		t.FailNow()
	}
}

// Benchmark the generation of P256 keys.
func BenchmarkGenerateKeyP256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(rand.Reader, elliptic.P256(), nil); err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}

// Benchmark the generation of P256 shared keys.
func BenchmarkGenSharedKeyP256(b *testing.B) {
	prv, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}

	for i := 0; i < b.N; i++ {
		_, err := prv.GenerateShared(&prv.PublicKey)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}

// Benchmark the encryption of 1Kb message using default P256 curve params.
func BenchmarkEncrypt1KbP256(b *testing.B) {
	prv, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}

	message := make([]byte, 1024)
	if _, err := rand.Read(message); err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(rand.Reader, &prv.PublicKey, message, nil, nil)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}

// Benchmark the decryption of 1Kb message encrypted using default P256 curve params.
func BenchmarkDecrypt1KbP256(b *testing.B) {
	prv, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}

	message := make([]byte, 1024)
	if _, err := rand.Read(message); err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}
	ct, err := Encrypt(rand.Reader, &prv.PublicKey, message, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		b.FailNow()
	}

	for i := 0; i < b.N; i++ {
		_, err := prv.Decrypt(rand.Reader, ct, nil, nil)
		if err != nil {
			fmt.Println(err.Error())
			b.FailNow()
		}
	}
}

// Verify that an encrypted message can be successfully decrypted.
func TestEncryptDecrypt(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	prv2, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, &prv2.PublicKey, message, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	pt, err := prv2.Decrypt(rand.Reader, ct, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !bytes.Equal(pt, message) {
		fmt.Println("ecies: plaintext doesn't match message")
		t.FailNow()
	}

	_, err = prv1.Decrypt(rand.Reader, ct, nil, nil)
	if err == nil {
		fmt.Println("ecies: encryption should not have succeeded")
		t.FailNow()
	}
}

// TestMarshalEncryption validates the encode/decode produces a valid
// ECIES encryption key.
func TestMarshalEncryption(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	out, err := MarshalPrivate(prv1)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	prv2, err := UnmarshalPrivate(out)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, &prv2.PublicKey, message, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	pt, err := prv2.Decrypt(rand.Reader, ct, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !bytes.Equal(pt, message) {
		fmt.Println("ecies: plaintext doesn't match message")
		t.FailNow()
	}

	_, err = prv1.Decrypt(rand.Reader, ct, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

}

type testCase struct {
	Curve    elliptic.Curve
	Name     string
	Expected bool
}

var testCases = []testCase{
	testCase{
		Curve:    elliptic.P224(),
		Name:     "P224",
		Expected: false,
	},
	testCase{
		Curve:    elliptic.P256(),
		Name:     "P256",
		Expected: true,
	},
	testCase{
		Curve:    elliptic.P384(),
		Name:     "P384",
		Expected: true,
	},
	testCase{
		Curve:    elliptic.P521(),
		Name:     "P521",
		Expected: true,
	},
}

// Test parameter selection for each curve, and that P224 fails automatic
// parameter selection (see README for a discussion of P224). Ensures that
// selecting a set of parameters automatically for the given curve works.
func TestParamSelection(t *testing.T) {
	for _, c := range testCases {
		testParamSelection(t, c)
	}
}

func testParamSelection(t *testing.T, c testCase) {
	params := ParamsFromCurve(c.Curve)
	if params == nil && c.Expected {
		fmt.Printf("%s (%s)\n", ErrInvalidParams.Error(), c.Name)
		t.FailNow()
	} else if params != nil && !c.Expected {
		fmt.Printf("ecies: parameters should be invalid (%s)\n",
			c.Name)
		t.FailNow()
	}

	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Printf("%s (%s)\n", err.Error(), c.Name)
		t.FailNow()
	}

	prv2, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Printf("%s (%s)\n", err.Error(), c.Name)
		t.FailNow()
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, &prv2.PublicKey, message, nil, nil)
	if err != nil {
		fmt.Printf("%s (%s)\n", err.Error(), c.Name)
		t.FailNow()
	}

	pt, err := prv2.Decrypt(rand.Reader, ct, nil, nil)
	if err != nil {
		fmt.Printf("%s (%s)\n", err.Error(), c.Name)
		t.FailNow()
	}

	if !bytes.Equal(pt, message) {
		fmt.Printf("ecies: plaintext doesn't match message (%s)\n",
			c.Name)
		t.FailNow()
	}

	_, err = prv1.Decrypt(rand.Reader, ct, nil, nil)
	if err == nil {
		fmt.Printf("ecies: encryption should not have succeeded (%s)\n",
			c.Name)
		t.FailNow()
	}

}

// Ensure that the basic public key validation in the decryption operation
// works.
func TestBasicKeyValidation(t *testing.T) {
	badBytes := []byte{0, 1, 5, 6, 7, 8, 9}

	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, &prv.PublicKey, message, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	for _, b := range badBytes {
		ct[0] = b
		_, err := prv.Decrypt(rand.Reader, ct, nil, nil)
		if err != ErrInvalidPublicKey {
			fmt.Println("ecies: validated an invalid key")
			t.FailNow()
		}
	}
}
