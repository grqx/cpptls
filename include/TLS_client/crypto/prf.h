#ifndef TLS_CLIENT_CRYPTO_PRF_H
#define TLS_CLIENT_CRYPTO_PRF_H

#include <TLS_client/crypto/hash.h>
#include <TLS_client/crypto/hmac.h>
#include <TLS_client/tls_types.h>

#include <cstdint>
#include <vector>

/*
 * First, we define a data expansion function, P_hash(secret, data),
 * that uses a single hash function to expand a secret and seed into an
 * arbitrary quantity of output:
 *
 *    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 *                           HMAC_hash(secret, A(2) + seed) +
 *                           HMAC_hash(secret, A(3) + seed) + ...
 *
 * where + indicates concatenation.
 *
 * A() is defined as:
 *
 *    A(0) = seed
 *    A(i) = HMAC_hash(secret, A(i-1))
 *
 * P_hash can be iterated as many times as necessary to produce the
 * required quantity of data.  For example, if P_SHA256 is being used to
 * create 80 bytes of data, it will have to be iterated three times
 * (through A(3)), creating 96 bytes of output data; the last 16 bytes
 * of the final iteration will then be discarded, leaving 80 bytes of
 * output data.
 */
std::vector<uint8_t> TLS_P_hash(const std::vector<uint8_t> &secret,
                                const std::vector<uint8_t> &seed, int len, const HashInfo &PRFhi)
{
    /*
     * In this section, we define one PRF, based on HMAC.  This PRF with the
     * SHA-256 hash function is used for all cipher suites defined in this
     * document and in TLS documents published prior to this document when
     * TLS 1.2 is negotiated.  New cipher suites MUST explicitly specify a
     * PRF and, in general, SHOULD use the TLS PRF with SHA-256 or a
     * stronger standard hash function.
     */
    std::vector<uint8_t> ret;
    // A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
    std::vector<std::vector<uint8_t>> vecOfVecs_A(1, seed);
    while (ret.size() < len) {
        vecOfVecs_A.push_back(hmac(secret, vecOfVecs_A.back(), PRFhi));
        std::vector<uint8_t> concatd = vecOfVecs_A.back();  // A.back() + seed
        concatd.insert(concatd.end(), seed.begin(), seed.end());
        auto hmac_ = hmac(secret, concatd, PRFhi);
        ret.insert(ret.end(), hmac_.begin(), hmac_.end());
    }
    ret.resize(len);
    return ret;
}

/*
 * TLS's PRF is created by applying P_hash to the secret as:
 *
 *     PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 *
 * where + indicates concatenation.
 *
 * The label is an ASCII string.  It should be included in the exact
 * form it is given without a length byte or trailing null character.
 * For example, the label "slithy toves" would be processed by hashing
 * the following bytes:
 *
 *   73 6C 69 74 68 79 20 74 6F 76 65 73
 */
std::vector<uint8_t> TLS_PRF(const std::vector<uint8_t> &secret, std::string label,
                             const std::vector<uint8_t> &seed, int len, const HashInfo &PRFhi)
{
    std::vector<uint8_t> realSeed;
    realSeed.reserve(label.size() + seed.size());
    std::copy(label.begin(), label.end(), std::back_inserter(realSeed));
    std::copy(seed.begin(), seed.end(), std::back_inserter(realSeed));
    std::vector<uint8_t> ret = TLS_P_hash(secret, realSeed, len, PRFhi);
    ret.resize(len);
    return ret;
}

#endif
