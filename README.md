Intro
=====
The go-ecies implements the Elliptic Curve Integrated Encryption Scheme.

This is a fork from the umbracle/ecies,
who did great job to extract the ECIES encryption from the go-ethereum package.

The package is designed to be compliant with the appropriate NIST
standards, and therefore doesn't support the full SEC 1 algorithm set.

Status
======
The ECIES should is ready for use. It is already used as is in the Foundries.io
projects (e.g. foundriesio/fioconfig) for the encryption of device configuration files.

The ASN.1 support is only complete so far, as to support the listed algorithms before.

Supported Ciphers
=================
A list of supported curves was selected based on NIST SP 800-186 Draft.  Thus, for example, the
Koblitz curves (`secpXXXk1` in SEC 2) are not supported by Golang and not recommended by NIST.

Note: If one wants to use the Koblitz curves with this package, their minimal implementation can be
found in e.g. https://github.com/decred/dcrd/blob/master/dcrec/secp256k1/ellipticadaptor.go.

The default symmetric cipher and hash parameters are the following:
    +-------+-------------+---------+--------------+
    | Curve |    Cipher   |  Hash   |   Auth Tag   |
    +-------+-------------+---------+--------------+
    | P-256 | AES-128-CTR | SHA-256 | HMAC-SHA-256 |
    +-------+-------------+---------+--------------+
    | P-384 | AES-192-CTR | SHA-384 | HMAC-SHA-384 |
    +-------+-------------+---------+--------------+
    | P-521 | AES-256-CTR | SHA-512 | HMAC-SHA-512 |
    +-------+-------------+---------+--------------+

The P-224 curve is not supported. As per SEC 1 section 3.11 guidance it is too weak to protect
sensitive data beyond 2030. The P-256 is currently the default curve supported by the Foundries.io
LmP platform. So, we recommend to use P-256 default parameters from the above table unless you have
a specific requirement for a stronger encryption strength.

The key derivation function used: NIST SP 800-56c Concatenation KDF.

The CMAC based message tag and the CBC cipher schema are currently not supported.

Benchmark
=========

The most recent test benchmark results:
```
goos: linux
goarch: amd64
pkg: github.com/umbracle/ecies
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
BenchmarkGenerateKeyP256      61060    17358 ns/op
BenchmarkGenSharedKeyP256     17931    67049 ns/op
BenchmarkEncrypt1KbP256       10000    100334 ns/op
BenchmarkDecrypt1KbP256       14184    105888 ns/op
```

License
=======

The go-ecies is released under the same license as the Go source code.
See the LICENSE file for details.

Reference
=========
* SEC 1 v2: Standards for Efficient Cryptography: Elliptic Curve Cryptography.
  Certicom Research. May 2009. http://www.secg.org/sec1-v2.pdf
* SEC 2 v2: Standards for Efficient Cryptography: Recommended Elliptic Curve Domain Parameters.
  Certicom Research. January 2010. https://www.secg.org/sec2-v2.pdf
* NIST SP 800-186 Draft: Recommendations for Discrete Logarithm-Based Cryptography:
  Elliptic Curve Domain Parameters. National Institute of Standards and Technology, October 2019.
  https://csrc.nist.gov/publications/detail/sp/800-186/draft
* NIST SP 800-56a Rev 3: Recommendation for Pair-Wise Key Establishment Schemes Using Discrete
  Logarithm Cryptography. National Institute of Standards and Technology, April 2018.
  https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final
* NIST SP 800-56c Rev 2: Recommendation for Key-Derivation Methods in Key-Establishment Schemes.
  National Institute of Standards and Technology. August 2020.
  https://csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final
