# LIBCPPTLS
This is just a discarded draft of a RFC 5246(TLS 1.2) implementation. Many details are **NOT** standard-conformant, and the only supported Key Exchange Algorithm is RSA.

> [!WARNING]  
> This implementation is just a draft, and is **NOT** secure. **DO NOT** use this library in production.

---

## Dependencies
* OpenSSL(**Required**)

## Cipher Suites Implemented
```cpp
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
```
Note that GCM is not supported. There are some flaws in `TLS_Session::encPlaintext`/`decPlaintext` for AEAD ciphers'.

## Compression
Compression is **NOT** implemented at all.

## Downgrade Attack
Downgrade detection by checking the server random is **NOT** implemented at all.

## Versions
TLS 1.3 is **NOT** implemented. The only supported TLS version is TLS 1.2.

## Packet Parsing
TLS Record parsing is **NOT** properly done.
