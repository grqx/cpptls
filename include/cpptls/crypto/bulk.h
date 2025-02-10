#ifndef LIBCPPTLS_CRYPTO_BULK_H
#define LIBCPPTLS_CRYPTO_BULK_H

#include <cstdint>
#include <vector>

struct BlockOrStreamEncFnArgsType {
    const std::vector<uint8_t> &key;
    const std::vector<uint8_t> &iv;
    const std::vector<uint8_t> &data;
};
typedef std::vector<uint8_t> (*BlockOrStreamEncFnType)(BlockOrStreamEncFnArgsType args);
struct AEADEncFnArgsType {
    const std::vector<uint8_t> &key;
    // nonce (explicit), random and is sent explicitly
    // ought to be recordIVLength bytes
    const std::vector<uint8_t> &nonceExplicit;
    const std::vector<uint8_t> &data;
    const std::vector<uint8_t> &additionalData;
    // nonce (implicit), writeIV of the current side
    // ought to be fixedIVLength bytes
    const std::vector<uint8_t> &writeIV;
};
typedef std::vector<uint8_t> (*AEADEncFnType)(AEADEncFnArgsType args);

struct BlockOrStreamDecFnArgsType {
    const std::vector<uint8_t> &key;
    const std::vector<uint8_t> &iv;
    const std::vector<uint8_t> &encryptedData;
};
typedef std::vector<uint8_t> (*BlockOrStreamDecFnType)(BlockOrStreamDecFnArgsType args);
struct AEADDecFnArgsType {
    const std::vector<uint8_t> &key;
    // nonce (explicit), random and is sent explicitly
    // ought to be recordIVLength bytes
    const std::vector<uint8_t> &nonceExplicit;
    const std::vector<uint8_t> &encryptedData;
    const std::vector<uint8_t> &additionalData;
    // nonce (implicit), writeIV of the other side
    // ought to be fixedIVLength bytes
    const std::vector<uint8_t> &readIV;
};
typedef std::vector<uint8_t> (*AEADDecFnType)(AEADDecFnArgsType args);

struct CipherInfo {
    union EncFnUnionType {
        BlockOrStreamEncFnType bos;
        AEADEncFnType aead;
        explicit constexpr EncFnUnionType (BlockOrStreamEncFnType bos) : bos(bos) {}
        explicit constexpr EncFnUnionType (AEADEncFnType aead) : aead(aead) {}
    } enc;
    union DecFnUnionType {
        BlockOrStreamDecFnType bos;
        AEADDecFnType aead;
        explicit constexpr DecFnUnionType (BlockOrStreamDecFnType bos) : bos(bos) {}
        explicit constexpr DecFnUnionType (AEADDecFnType aead) : aead(aead) {}
    } dec;
    int keyMaterial;
    int recordIVLength;
    // IV length in key blocks
    uint8_t fixedIVLength;
    // -1 for stream ciphers
    // 0 for AEAD ciphers
    // >0 for block ciphers
    int blockSize;
    constexpr CipherInfo(BlockOrStreamEncFnType bos, BlockOrStreamDecFnType bosd, int km, int ivs, uint8_t fivl, int bs = -1)
        : enc(EncFnUnionType{bos}), dec(DecFnUnionType{bosd}), keyMaterial(km), recordIVLength(ivs), fixedIVLength(fivl), blockSize(bs) {}
    constexpr CipherInfo(AEADEncFnType aead, AEADDecFnType aeadd, int km, int ivs, uint8_t fivl)
        : enc(EncFnUnionType{aead}), dec(DecFnUnionType{aeadd}), keyMaterial(km), recordIVLength(ivs), fixedIVLength(fivl), blockSize(0) {}
};

#endif
