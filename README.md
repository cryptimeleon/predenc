# Predenc

The Cryptimeleon Predenc project contains various predicate encryption implementations such as attribute-based encryption or identity-based encryption.
Furthermore, it contains key encapsulation mechanisms based on predicate encryption schemes.

## Security Disclaimer
**WARNING: This library is meant to be used for prototyping and as a research tool *only*. It has not been sufficiently vetted for use in security-critical production environments. All implementations are to be considered experimental.**

## Implemented Schemes

* **Encryption schemes**:
    * Attribute-based:
        * Waters' ciphertext-policy attribute-based encryption scheme [Wat11]
        * Goyal et al.'s key-policy attribute-based encryption scheme [GPSW06]
    * Identity-based:
        * Fuzzy identity-based encryption [SW05]
        * Identity based encryption from the Weil pairing [BF01]
* **Key encapsulation mechanisms (KEM)**: We implement several KEMs based on the encryption schemes implemented in this library. Predenc provides KEMs for [Wat11], [GPSW06] and [SW05].

## References

[BF01] Dan Boneh and Matt Franklin. "Identity-Based Encryption from the Weil Pairing". In: Advances in Cryptology — CRYPTO 2001. CRYPTO 2001. Ed. by Joe Kilian. Vol. 2139. Lecture Notes in Computer Science.  Springer, Berlin, Heidelberg, August 2001, pp. 213-229.

[GPSW06] Vipul Goyal, Omkant Pandey, Amit Sahai, and Brent Waters. "Attribute-based encryption for fine-grained access control of encrypted data". In: ACM Conference on Computer and Communications Security. ACM, 2006, pages 89–98.

[Wat11] Brent Waters. Ciphertext-policy attribute-based encryption: An
expressive, efficient, and provably secure realization. In Public Key
Cryptography. Springer, 2011, pp. 53–70.


