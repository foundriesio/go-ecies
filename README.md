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

    +------------------+-------+---------+
    | Symmetric Cipher | Curve |   Hash  |
    +------------------+-------+---------+
    |     AES-128      | P-256 | SHA-256 |
    +------------------+-------+---------+
    |     AES-192      | P-384 | SHA-384 |
    +------------------+-------+---------+
    |     AES-256      | P-521 | SHA-512 |
    +------------------+-------+---------+
             
Key derivation function used: NIST SP 800-65a Concatenation KDF.

Curve P224 isn't supported because it does not provide a minimum security
level of AES128 with HMAC-SHA1. According to NIST SP 800-57, the security
level of P224 is 112 bits of security. Symmetric ciphers use CTR-mode;
message tags are computed using HMAC-<HASH> function.

The CMAC support is currently not present.

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
* SEC (Standard for Efficient Cryptography) 1, version 2.0: Elliptic
  Curve Cryptography; Certicom, May 2009.
  http://www.secg.org/sec1-v2.pdf
* GEC (Guidelines for Efficient Cryptography) 2, version 0.3: Test
  Vectors for SEC 1; Certicom, September 1999.
  http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
* NIST SP 800-56a: Recommendation for Pair-Wise Key Establishment Schemes
  Using Discrete Logarithm Cryptography. National Institute of Standards
  and Technology, May 2007.
  http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf
* Suite B Implementer’s Guide to NIST SP 800-56A. National Security
  Agency, July 28, 2009.
  http://www.nsa.gov/ia/_files/SuiteB_Implementer_G-113808.pdf
* NIST SP 800-57: Recommendation for Key Management – Part 1: General
  (Revision 3). National Institute of Standards and Technology, July
  2012.
  http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf
