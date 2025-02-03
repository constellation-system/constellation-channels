# Constellation Communications API

**Constellation is under active development and has not undergone
rigorous security evaluation.  It cannot offer strong security
guarantees at present.**

## Quicklinks

* [Developer documentation for `devel` branch](https://constellation-system.github.io/constellation-channels/index.html)
* [Coverage reports for `devel` branch](https://constellation-system.github.io/constellation-channels/coverage/index.html)
* [Contribution guide](https://github.com/constellation-system/constellation-channels/blob/devel/CONTRIBUTING.md)

## Testing

Tests for this repository rely on generated X.509 certificates.  You
need to run the `gen_test_certs.sh` script once prior to testing.
Following that, the certificates should not need to be regenerated:

```sh
sh ./gen_test_certs.sh
cargo test
```
