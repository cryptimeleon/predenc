![Build Status](https://github.com/cryptimeleon/predenc/workflows/Development%20Java%20CI/badge.svg)
![Build Status](https://github.com/cryptimeleon/predenc/workflows/Release%20Java%20CI/badge.svg)
![Build Status](https://github.com/cryptimeleon/predenc/workflows/Scheduled%20Release%20Java%20CI/badge.svg)
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

## Quickstart

### Installation With Maven
To add the newest Predenc version as a dependency, add this to your project's POM:

```xml
<dependency>
    <groupId>org.cryptimeleon</groupId>
    <artifactId>predenc</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Installation With Gradle

Predenc is published via Maven Central.
Therefore, you need to add `mavenCentral()` to the `repositories` section of your project's `build.gradle` file.
Then, add `implementation group: 'org.cryptimeleon', name: 'predenc', version: '1.0.0'` to the `dependencies` section of your `build.gradle` file.

For example:

```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation group: 'org.cryptimeleon', name: 'predenc', version: '1.0.0'
}
```

### Tutorials

Predenc uses the mathematical facilities of our [Math library](https://github.com/cryptimeleon/math).
Therefore, we recommend you go through our [short Math tutorial](https://cryptimeleon.github.io/getting-started/5-minute-tutorial.html) to get started.

## Miscellaneous Information

- Official Documentation can be found [here](https://cryptimeleon.github.io/).
    - The *For Contributors* area includes information on how to contribute.
- Predenc adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
- The changelog can be found [here](CHANGELOG.md).
- Predenc is licensed under Apache License 2.0, see [LICENSE file](LICENSE).

## Authors
The library was implemented at Paderborn University in the research group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/).

## References

[BF01] Dan Boneh and Matt Franklin. "Identity-Based Encryption from the Weil Pairing". In: Advances in Cryptology — CRYPTO 2001. CRYPTO 2001. Ed. by Joe Kilian. Vol. 2139. Lecture Notes in Computer Science.  Springer, Berlin, Heidelberg, August 2001, pp. 213-229.

[SW05] Amit Sahai and Brent Waters. "Fuzzy Identity-Based Encryption". In: Advances in Cryptology – EUROCRYPT 2005 (pp. 457–473). Springer Berlin Heidelberg.

[GPSW06] Vipul Goyal, Omkant Pandey, Amit Sahai, and Brent Waters. "Attribute-based encryption for fine-grained access control of encrypted data". In: ACM Conference on Computer and Communications Security. ACM, 2006, pages 89–98.

[Wat11] Brent Waters. Ciphertext-policy attribute-based encryption: An
expressive, efficient, and provably secure realization. In Public Key
Cryptography. Springer, 2011, pp. 53–70.


