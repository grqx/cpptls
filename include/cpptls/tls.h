#ifndef LIBCPPTLS_TLS_H
#define LIBCPPTLS_TLS_H

#include <cpptls/crypto/cipher_suite.h>
#include <cpptls/crypto/prf.h>
#include <cpptls/endian_utils.h>
#include <cpptls/crypto/cert.h>
#include <cpptls/tls_exceptions.h>
#include <cpptls/tls_extensions.h>
#include <cpptls/tls_genrand.h>
#include <cpptls/tls_types.h>
#include <cpptls/unique_container.h>
#include <cpptls/export.h>

#include <cstdint>
#include <ctime>
#include <fstream>
#include <list>
#include <optional>
#include <random>
#include <sstream>
#include <vector>

#include "debug.h"
int main();

class LIBCPPTLS_API TLS_Session
{
   private:
    std::vector<uint8_t> m_sessionID;
    std::vector<uint8_t> m_clientRandom;
    std::vector<uint8_t> m_serverRandom;
    std::vector<uint8_t> m_serverPubKey;
    std::vector<uint8_t> m_preMasterSecret;
    std::vector<uint8_t> m_masterSecret;
    UniqueContainer<std::unique_ptr<TLS_Extension>, std::vector> m_exts;
    mutable std::optional<CipherSuiteInfo> m_csInfo;
    const CipherSuiteInfo &getCSInfo() const noexcept
    {
        if (!m_csInfo) m_csInfo = getCipherSuiteInfo(*m_selectedCipherSuite);
        return *m_csInfo;
    }
    mutable std::vector<uint8_t> m_keyBlock;
    const std::vector<uint8_t> &getKeyBlock() const noexcept
    {
        using namespace std::string_literals;
        if (m_keyBlock.empty() && !m_masterSecret.empty()) {
            std::vector<uint8_t> concatd{m_serverRandom.begin(), m_serverRandom.end()};
            concatd.insert(concatd.end(), m_clientRandom.begin(), m_clientRandom.end());
            m_keyBlock = TLS_PRF(m_masterSecret, "key expansion"s, concatd,
                                 2 * (getCSInfo().mi.macKeyLength + getCSInfo().ci.keyMaterial +
                                      getCSInfo().ci.fixedIVLength),
                                 getCSInfo().PRFHashInfo);
            // key_block = PRF(SecurityParameters.master_secret, "key expansion",
            //     SecurityParameters.server_random +
            //     SecurityParameters.client_random);
        }
        return m_keyBlock;
    }
    mutable std::vector<uint8_t> m_clientWriteMACKey;
    const std::vector<uint8_t> &getClientWriteMACKey() const noexcept
    {
        if (m_clientWriteMACKey.empty() && !m_masterSecret.empty()) {
            const auto &kbb = getKeyBlock().begin();
            m_clientWriteMACKey = {kbb, kbb + getCSInfo().mi.macKeyLength};
        }
        return m_clientWriteMACKey;
    }
    mutable std::vector<uint8_t> m_serverWriteMACKey;
    const std::vector<uint8_t> &getServerWriteMACKey() const noexcept
    {
        if (m_serverWriteMACKey.empty() && !m_masterSecret.empty()) {
            const auto &kbb = getKeyBlock().begin();
            m_serverWriteMACKey = {kbb + getCSInfo().mi.macKeyLength,
                                   kbb + 2 * getCSInfo().mi.macKeyLength};
        }
        return m_serverWriteMACKey;
    }
    mutable std::vector<uint8_t> m_clientWriteKey;
    const std::vector<uint8_t> &getClientWriteKey() const noexcept
    {
        if (m_clientWriteKey.empty() && !m_masterSecret.empty()) {
            const auto &kbb = getKeyBlock().begin();
            m_clientWriteKey = {kbb + 2 * getCSInfo().mi.macKeyLength,
                                kbb + 2 * getCSInfo().mi.macKeyLength + getCSInfo().ci.keyMaterial};
        }
        return m_clientWriteKey;
    }
    mutable std::vector<uint8_t> m_serverWriteKey;
    const std::vector<uint8_t> &getServerWriteKey() const noexcept
    {
        if (m_serverWriteKey.empty() && !m_masterSecret.empty()) {
            const auto &kbb = getKeyBlock().begin();
            m_serverWriteKey = {
                kbb + 2 * getCSInfo().mi.macKeyLength + getCSInfo().ci.keyMaterial,
                kbb + 2 * getCSInfo().mi.macKeyLength + 2 * getCSInfo().ci.keyMaterial};
        }
        return m_serverWriteKey;
    }
    mutable std::vector<uint8_t> m_clientWriteIV;
    const std::vector<uint8_t> &getClientWriteIV() const noexcept
    {
        if (m_clientWriteIV.empty() && !m_masterSecret.empty()) {
            const auto &kbb = getKeyBlock().begin();
            m_clientWriteIV = {
                kbb + 2 * getCSInfo().mi.macKeyLength + 2 * getCSInfo().ci.keyMaterial,
                kbb + 2 * getCSInfo().mi.macKeyLength + 2 * getCSInfo().ci.keyMaterial +
                    getCSInfo().ci.fixedIVLength};
        }
        return m_clientWriteIV;
    }
    mutable std::vector<uint8_t> m_serverWriteIV;
    const std::vector<uint8_t> &getServerWriteIV() const noexcept
    {
        if (m_serverWriteIV.empty() && !m_masterSecret.empty()) {
            const auto &kbb = getKeyBlock().begin();
            m_serverWriteIV = {kbb + 2 * getCSInfo().mi.macKeyLength +
                                   2 * getCSInfo().ci.keyMaterial + getCSInfo().ci.fixedIVLength,
                               kbb + 2 * getCSInfo().mi.macKeyLength +
                                   2 * getCSInfo().ci.keyMaterial + 2 * getCSInfo().ci.fixedIVLength};
        }
        return m_serverWriteIV;
    }
    std::vector<uint8_t> m_handshakeMessages;
    // cipher suites / compression methods in network byte-order ready to be sent
    std::vector<uint8_t> m_cipherSuites;
    std::vector<uint8_t> m_compressionMethods;
    std::optional<CipherSuite> m_selectedCipherSuite;
    std::optional<CompressionMethod> m_selectedCompressionMethod;
    TLS_Version m_vsn;
    TLS_State_ m_state_ = TLS_State_::Created;
    uint64_t m_seqNum = 0;
    // sequence number for the other side of the connection
    uint64_t m_seqOther = 0;
    // flag: whether client/server has changed cipher suite
    // TODO: deprecate this, use two bools instead, no space will be wasted
    // since member variables are stored contiguously
    uint8_t m_cSChanged = 0;

   public:
    friend int ::main();  // for debugging only
    const TLS_State_ &getState() const noexcept
    {
        return m_state_;
    }

    void TLS_setCipherSuites(const std::list<CipherSuite> &css)
    {
        m_cipherSuites.clear();
        m_cipherSuites.reserve(2 * css.size());
        for (auto &&cs : css)
            stdcopy_to_big_endian(static_cast<uint16_t>(cs), std::back_inserter(m_cipherSuites), 2);
    }

    void TLS_setCompressionMethods(const std::list<CompressionMethod> &cms)
    {
        m_compressionMethods.clear();
        m_compressionMethods.reserve(cms.size());
        for (auto &&cm : cms) m_compressionMethods.push_back(static_cast<uint8_t>(cm));
    }

    TLS_Session(const TLS_Version &version, const std::list<CipherSuite> &css,
                const std::list<CompressionMethod> &cms, UniqueContainer<std::unique_ptr<TLS_Extension>, std::vector> &&exts = {})
        : m_vsn(TLS_Version::TLS_1_2), m_exts(std::move(exts))
    {
        TLS_setCipherSuites(css);
        TLS_setCompressionMethods(cms);
        if (version == TLS_Version::TLS_1_3) m_exts.emplace_back(std::move(std::make_unique<TLSExt_SupportedVersions>(m_vsn)));
    }

    std::vector<uint8_t> TLS_generateClientRandom()
    {
        if (m_clientRandom.size() == 32) return m_clientRandom;
        std::vector<uint8_t> data;
        data.reserve(32);
        auto currentTime = std::time(nullptr);

        stdcopy_to_big_endian(static_cast<uint32_t>(currentTime), std::back_inserter(data));

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);

        for (size_t i = 4; i < 32; ++i) {
            data.push_back(dis(gen));
        }
        m_clientRandom = data;
        return m_clientRandom;
    }

    [[nodiscard]] TLSPlaintext TLS_writeClientHello()
    {
        // if (m_state_ != TLS_State_::Created) ;  // do something, maybe make ret
        // optional
        std::vector<uint8_t> vec(39);
        vec[0] = static_cast<uint8_t>(HandshakeType::ClientHello);
        // vec[4, 5]: Client Version
        stdcopy_to_big_endian(static_cast<uint16_t>(m_vsn), vec.begin() + 4, 2);
        // vec[6 ~ 37]: Client Random
        auto cr = TLS_generateClientRandom();
        std::copy(cr.begin(), cr.end(), vec.begin() + 6);

        // vec[38]: Session ID
        auto sidSize = m_sessionID.size();
        if (sidSize > UINT8_MAX)
            throw std::overflow_error("TLS Session ID length overflowed UINT8_MAX");
        vec[38] = static_cast<uint8_t>(sidSize);
        if (sidSize) std::copy(m_sessionID.begin(), m_sessionID.end(), std::back_inserter(vec));

        // CipherSuites
        auto cipherSuitesSize = m_cipherSuites.size();
        if (cipherSuitesSize > UINT16_MAX)
            throw std::overflow_error("Cipher Suites length overflowed UINT16_MAX");
        stdcopy_to_big_endian(static_cast<uint16_t>(cipherSuitesSize), std::back_inserter(vec));
        if (cipherSuitesSize)
            std::copy(m_cipherSuites.begin(), m_cipherSuites.end(), std::back_inserter(vec));

        // CompressionMethods
        auto compressionMethodsSize = m_compressionMethods.size();
        if (compressionMethodsSize > UINT8_MAX)
            throw std::overflow_error("Compression Methods length overflowed UINT8_MAX");
        vec.push_back(static_cast<uint8_t>(compressionMethodsSize));
        if (compressionMethodsSize)
            std::copy(m_compressionMethods.begin(), m_compressionMethods.end(),
                      std::back_inserter(vec));

        // Extensions, TODO
        // do not need to write extension length when there are no extensions
        if (!m_exts.empty()) {
            size_t extsSize = 0;
            for (auto &&ext : m_exts) {
                auto r = ext->serialiseInto();
                if (r >= 0) extsSize += r;
                else throw TLS_Alert(TLS_AlertCode::InternalError, true);
            }
            auto idx = vec.size();
            vec.resize(idx + 2 + extsSize);
            copy_to_ptr_big_endian(extsSize, vec.data() + idx, 2);
            idx += 2;
            for (auto &&ext : m_exts) {
                auto r = ext->serialiseInto(vec.data() + idx);
                if (r >= 0) idx += r;
                else throw TLS_Alert(TLS_AlertCode::InternalError, true);
            }
        }

        // vec[1, 2, 3]: length of the rest of the packet
        size_t pktSize = vec.size() - 4;
        if (pktSize > UINT24_MAX)
            throw std::overflow_error("Client Hello Handshake length overflowed UINT24_MAX");
        stdcopy_to_big_endian(static_cast<uint32_t>(pktSize), vec.begin() + 1, 3);
        m_state_ = TLS_State_::ClientHelloDone;
        std::copy(vec.begin(), vec.end(), std::back_inserter(m_handshakeMessages));
        return {vec, ContentType::Handshake, m_vsn};
    }

    // NOTE: This is not standard conformant, see Appendix D.4. of RFC 5246
    /// @brief parses server hello
    /// @param serverHello const lvalue reference to a TLSPlaintext struct, should
    /// contain the server hello/server hello done packet
    /// @return true if succeeded, false if failed
    bool TLS_parseServerHello(const TLSPlaintext &serverHello)
    {
        if (m_state_ != TLS_State_::ClientHelloDone) return false;
        if (serverHello.contTyp != ContentType::Handshake)
            throw TLS_Alert(TLS_AlertCode::UnexpectedMessage, true);
        if (serverHello.recordVersion != m_vsn) return false;

        auto hs = TLS_Handshake::parse(serverHello, true);
        if (!hs) return false;
        auto parsed = 0;
        auto csize = hs->m_cont.size();
        if (hs->m_ht == HandshakeType::ServerDn) {
            if (!m_serverRandom.size() || !m_serverPubKey.size() || !m_sessionID.size())
                throw TLS_Alert(TLS_AlertCode::HandshakeFailure,
                                true);  // early server hello done
            m_state_ = TLS_State_::ServerHelloDone;
        } else if (hs->m_ht == HandshakeType::ServerHello) {
            if (csize < 39) throw TLS_Alert(TLS_AlertCode::DecodeError, true);
            if (m_serverRandom.size())
                throw TLS_Alert(TLS_AlertCode::UnexpectedMessage,
                                true);  // duplicate server hello

            auto serverVsn = from_big_endian<TLS_Version>(hs->m_cont.data() + parsed);
            if (serverVsn != m_vsn)
                throw TLS_Alert(TLS_AlertCode::ProtocolVersion,
                                true);  // wrong proto ver
            parsed += sizeof(TLS_Version);

            std::copy(hs->m_cont.begin() + parsed, hs->m_cont.begin() + parsed + 32,
                      std::back_inserter(m_serverRandom));
            parsed += 32;

            uint8_t sidLen = hs->m_cont[parsed];
            parsed++;
            if (parsed + sidLen > csize)
                throw TLS_Alert(TLS_AlertCode::DecodeError,
                                true);  // unexpected end-of-packet

            m_sessionID.clear();
            std::copy(hs->m_cont.begin() + parsed, hs->m_cont.begin() + parsed + sidLen,
                      std::back_inserter(m_sessionID));
            parsed += sidLen;

            // TODO: validate these two below

            if (parsed + sizeof(CipherSuite) > csize)
                throw TLS_Alert(TLS_AlertCode::DecodeError,
                                true);  // unexpected end-of-packet
            m_selectedCipherSuite = from_big_endian<CipherSuite>(hs->m_cont.data() + parsed);
            parsed += sizeof(CipherSuite);

            if (parsed + sizeof(CompressionMethod) > csize)
                throw TLS_Alert(TLS_AlertCode::DecodeError,
                                true);  // unexpected end-of-packet
            m_selectedCompressionMethod = static_cast<CompressionMethod>(hs->m_cont[parsed]);
            parsed += sizeof(CompressionMethod);

            // optional, should throw an error on unknown extensions
            if (parsed + sizeof(uint16_t) <= csize) {
                auto extLen = from_big_endian<uint16_t>(hs->m_cont.data() + parsed);
                if (parsed + extLen > csize)
                    throw TLS_Alert(TLS_AlertCode::DecodeError,
                                    true);  // unexpected end-of-packet
                parsed += extLen;
                throw TLS_Alert(TLS_AlertCode::UnsupportedExtension, true);
            }
        } else if (hs->m_ht == HandshakeType::Certificate) {
            if (csize < 3)
                throw TLS_Alert(TLS_AlertCode::DecodeError,
                                true);  // unexpected end-of-packet
            auto certSize = from_big_endian<uint32_t, 3>(hs->m_cont.data());
            parsed += 3;

            if (parsed + certSize > csize)
                throw TLS_Alert(TLS_AlertCode::DecodeError,
                                true);  // unexpected end-of-packet
            std::vector<uint8_t> certs{hs->m_cont.begin() + parsed,
                                       hs->m_cont.begin() + parsed + certSize};
            parsed += certSize;

            m_serverPubKey = ChatGPT4o::getPubKey(certs);
        } else
            return false;
        if (parsed < csize)
            throw TLS_Alert(TLS_AlertCode::DecodeError,
                            true);  // invalid redundant content
        std::copy(serverHello.realCont.begin(), serverHello.realCont.end(),
                  std::back_inserter(m_handshakeMessages));
        return true;
    }

    std::optional<std::list<TLSPlaintext>> TLS_writeClientKex()
    {
        using namespace std::string_literals;
        if (m_state_ != TLS_State_::ServerHelloDone) return std::nullopt;
        m_preMasterSecret = std::vector<uint8_t>(48, 0);
        stdcopy_to_big_endian(static_cast<uint16_t>(m_vsn), m_preMasterSecret.begin());
        fillRand(m_preMasterSecret, m_preMasterSecret.begin() + 2, m_preMasterSecret.end());
        auto pmsEnc =
            ChatGPT4o::encRSA(m_preMasterSecret, ChatGPT4o::deserializePublicKey(m_serverPubKey));
        auto pmsEncSize = pmsEnc.size();
        if (!pmsEncSize) return std::nullopt;
        std::vector<uint8_t> hsCont;
        hsCont.reserve(2 + pmsEncSize);

        if (pmsEncSize > UINT16_MAX)
            throw std::overflow_error("Encrypted Pre-Master Secret length overflowed UINT16_MAX");
        stdcopy_to_big_endian(static_cast<uint16_t>(pmsEncSize), std::back_inserter(hsCont));
        std::copy(pmsEnc.begin(), pmsEnc.end(), std::back_inserter(hsCont));
        Debugging::pu8Vec(hsCont, 8, true, "ClientKex content");
        TLS_Handshake ckx{HandshakeType::ClientKex, hsCont};
        if (!m_masterSecret.size()) {
            std::vector<uint8_t> concatdRandoms{m_clientRandom.begin(), m_clientRandom.end()};
            concatdRandoms.insert(concatdRandoms.end(), m_serverRandom.begin(),
                                  m_serverRandom.end());
            m_masterSecret = TLS_PRF(m_preMasterSecret, "master secret"s, concatdRandoms, 48,
                                     getCSInfo().PRFHashInfo);
        }
        auto ckxPacket = ckx.toPacket(m_vsn);
        std::copy(ckxPacket.realCont.begin(), ckxPacket.realCont.end(),
                  std::back_inserter(m_handshakeMessages));

        m_state_ = TLS_State_::KexDone;
        m_cSChanged |= CipherSpecChangedFlag::clientChanged;
        auto finishedPacket = TLS_writeFinished();
        if (!finishedPacket) return std::nullopt;
        return {{ckxPacket, {{0x01}, ContentType::ChangeCipherSpec, m_vsn}, *finishedPacket}};
    }

    std::optional<TLSPlaintext> TLS_writeFinished()
    {
        using namespace std::string_literals;
        if (m_state_ != TLS_State_::KexDone) return std::nullopt;
        // PRF(master_secret, finished_label, Hash(handshake_messages))
        //     [0..verify_data_length-1];
        /*
         * Hash denotes a Hash of the handshake messages.  For the PRF
         * defined in Section 5, the Hash MUST be the Hash used as the basis
         * for the PRF.  Any cipher suite which defines a different PRF MUST
         * also define the Hash to use in the Finished computation.
         */
        auto verifyData = TLS_PRF(m_masterSecret, "client finished"s,
                                  getCSInfo().PRFHashInfo.hashFn(m_handshakeMessages),
                                  getCSInfo().verifyDataLength, getCSInfo().PRFHashInfo);
        Debugging::pu8Vec(verifyData, 8, true, "verifyData");
        TLS_Handshake cfinished{HandshakeType::Finished, verifyData};
        auto packet = cfinished.toPacket(m_vsn);
        Debugging::pu8Vec(packet.realCont, 8, true, "Client Finished content");
        packet.realCont = encPlainText(packet);
        Debugging::pu8Vec(packet.realCont, 8, true, "Client Finished content(encrypted)");
        m_state_ = TLS_State_::ClientFinished_;
        return {packet};
    }

    std::vector<uint8_t> encPlainText(const TLSPlaintext &tpt)
    {
        if (!(m_cSChanged & CipherSpecChangedFlag::clientChanged))
            throw std::runtime_error(
                "Client hasn't sent change cipher spec but requested encryption");
        std::vector<uint8_t> dataToHash;
        dataToHash.reserve(getCSInfo().ci.blockSize ? 13 + tpt.realCont.size() : 13);
        stdcopy_to_big_endian(m_seqNum++, std::back_inserter(dataToHash));
        dataToHash.push_back(static_cast<uint8_t>(tpt.contTyp));
        stdcopy_to_big_endian(m_vsn, std::back_inserter(dataToHash), 2);
        stdcopy_to_big_endian(tpt.realCont.size(), std::back_inserter(dataToHash), 2);
        if (getCSInfo().ci.blockSize) {  // block or stream cipher
            /*
            * stream-ciphered struct {
            *     opaque content[TLSCompressed.length];
            *     opaque MAC[SecurityParameters.mac_length];
            * } GenericStreamCipher;
            *
            * struct {
            *     opaque IV[SecurityParameters.record_iv_length];
            *     block-ciphered struct {
            *         opaque content[TLSCompressed.length];
            *         opaque MAC[SecurityParameters.mac_length];
            *         uint8 padding[GenericBlockCipher.padding_length];
            *         uint8 padding_length;
            *     };
            * } GenericBlockCipher;
            */
            dataToHash.insert(dataToHash.end(), tpt.realCont.begin(), tpt.realCont.end());
            Debugging::pu8Vec(dataToHash, 8, true, "data to hash");

            auto hash_ = hmac(getClientWriteMACKey(), dataToHash, getCSInfo().mi.MACHashInfo);

            auto dataWithHash = tpt.realCont;
            Debugging::pu8Vec(dataWithHash, 8, true, "data");
            dataWithHash.insert(dataWithHash.end(), hash_.begin(), hash_.end());

            if (getCSInfo().ci.blockSize > 0) {  // pad if using block cipher
                /* 
                 * padding
                 *    Padding that is added to force the length of the plaintext to be
                 *    an integral multiple of the block cipher's block length.  The
                 *    padding MAY be any length up to 255 bytes, as long as it results
                 *    in the TLSCiphertext.length being an integral multiple of the
                 *    block length.  Lengths longer than necessary might be desirable to
                 *    frustrate attacks on a protocol that are based on analysis of the
                 *    lengths of exchanged messages.  Each uint8 in the padding data
                 *    vector MUST be filled with the padding length value.  The receiver
                 *    MUST check this padding and MUST use the bad_record_mac alert to
                 *    indicate padding errors.
                 *
                 * padding_length
                 *    The padding length MUST be such that the total size of the
                 *    GenericBlockCipher structure is a multiple of the cipher's block
                 *    length.  Legal values range from zero to 255, inclusive.  This
                 *    length specifies the length of the padding field exclusive of the
                 *    padding_length field itself.
                 */
                uint8_t padding_ =
                    getCSInfo().ci.blockSize - (dataWithHash.size() % getCSInfo().ci.blockSize);
                // random padding
                padding_ +=
                    randInt((255U - padding_) / getCSInfo().ci.blockSize) * getCSInfo().ci.blockSize;
                dataWithHash.resize(dataWithHash.size() + padding_, padding_ - 1);
            }
            Debugging::pu8Vec(dataWithHash, 8, true, "dataWithHash(after padding)");

            auto encIV = genRand(getCSInfo().ci.recordIVLength);
            auto enc = getCSInfo().ci.enc.bos({getClientWriteKey(), encIV, dataWithHash});
            encIV.insert(encIV.end(), enc.begin(), enc.end());
            return encIV;
        } else {  // AEAD cipher
            /*
            * struct {
            *    opaque nonce_explicit[SecurityParameters.record_iv_length];
            *    aead-ciphered struct {
            *        opaque content[TLSCompressed.length];
            *    };
            * } GenericAEADCipher;
            */
            // auto nonceExplicit = genRand(getCSInfo().ci.recordIVLength);  // SecurityParameters.record_iv_length
            // some1 said that the nonce_explicit should be seq num
            // some1 said that 000001 is appended to the nonce to make it 128bit
            std::vector<uint8_t> nonceExplicit(getCSInfo().ci.recordIVLength);
            fillRand(nonceExplicit, nonceExplicit.begin(), nonceExplicit.begin() + getCSInfo().ci.recordIVLength - 3);
            copy_to_ptr_big_endian(m_seqNum - 1, nonceExplicit.data() + getCSInfo().ci.recordIVLength - 3, 3);  // SecurityParameters.record_iv_length
            /*
             * AEADEncrypted = AEAD-Encrypt(write_key, nonce, plaintext,
             *                  additional_data)
             */
            // dataToHash = additional_data
            auto enc = getCSInfo().ci.enc.aead({getClientWriteKey(), nonceExplicit, tpt.realCont, dataToHash, getClientWriteIV()});
            auto decd = getCSInfo().ci.dec.aead({getClientWriteKey(), nonceExplicit, enc, dataToHash, getClientWriteIV()});
            if (enc != decd) throw TLS_Alert(TLS_AlertCode::InternalError, true);
            {
                Debugging::pu8Vec(dataToHash, 8, true, "AEAD AAD");
                Debugging::pu8Vec(tpt.realCont, 8, true, "raw data to encrypt");
                Debugging::pu8Vec(getClientWriteKey(), 8, true, "wkey");
                Debugging::pu8Vec(nonceExplicit, 8, true, "AEAD explicit nonce/IV");
                Debugging::pu8Vec(getClientWriteIV(), 8, true, "AEAD client write IV(salt)");
                Debugging::pu8Vec(enc, 8, true, "AEAD-encrypted data");
            }
            nonceExplicit.insert(nonceExplicit.end(), enc.begin(), enc.end());
            return nonceExplicit;
        }
        UNREACHABLE;
    }

    std::optional<TLSPlaintext> TLS_writeAppData(const std::vector<uint8_t> &data)
    {
        if (m_state_ != TLS_State_::ServerFinished_) return std::nullopt;
        TLSPlaintext packet{data, ContentType::Application, m_vsn};
        packet.realCont = encPlainText(packet);
        return {packet};
    }

    // parse server finished and server change cipher spec
    void TLS_parseServerFinished(const TLSPlaintext &packet)
    {
        if (m_state_ != TLS_State_::ClientFinished_)
            throw std::runtime_error("wrong state: expected ClientFinished_");
        if (packet.recordVersion != m_vsn) throw TLS_Alert(TLS_AlertCode::ProtocolVersion, true);
        int parsed = 0;
        if (packet.contTyp == ContentType::Handshake) {
            using namespace std::string_literals;
            auto packet_ = packet;
            packet_.realCont = decPlainText(packet);
            auto hs = TLS_Handshake::parse(packet_, true);
            if (hs->m_ht != HandshakeType::Finished)
                throw TLS_Alert(TLS_AlertCode::UnexpectedMessage, true);
            auto expected = TLS_PRF(m_masterSecret, "server finished"s,
                                    getCSInfo().PRFHashInfo.hashFn(m_handshakeMessages),
                                    getCSInfo().verifyDataLength, getCSInfo().PRFHashInfo);
            Debugging::pu8Vec(expected, 8, true, "expected server finished");
            Debugging::pu8Vec(hs->m_cont, 8, true, "got server finished");
            auto s = expected == hs->m_cont;
            std::cout << (s ? "true" : "false") << '\n';
            // FIXME
            // if (!s) throw TLS_Alert(TLS_AlertCode::HandshakeFailure, true);
            parsed = packet.realCont.size();
            m_state_ = TLS_State_::ServerFinished_;
        } else if (packet.contTyp == ContentType::ChangeCipherSpec) {
            if (packet.realCont.size() != 1) throw TLS_Alert(TLS_AlertCode::DecodeError, true);
            if (packet.realCont.front() != 0x01) throw TLS_Alert(TLS_AlertCode::DecodeError, true);
            parsed++;
            m_cSChanged |= CipherSpecChangedFlag::serverChanged;
        } else
            throw TLS_Alert(TLS_AlertCode::UnexpectedMessage, true);
        if (packet.realCont.size() > parsed) throw TLS_Alert(TLS_AlertCode::DecodeError, true);
    }

    std::vector<uint8_t> decPlainText(const TLSPlaintext &packet)
    {
        if (m_state_ != TLS_State_::ServerFinished_ && m_state_ != TLS_State_::ClientFinished_)
            throw std::runtime_error("Not in ServerFinished_/ClientFinished_ state");
        if (!(m_cSChanged & CipherSpecChangedFlag::serverChanged))
            throw TLS_Alert(TLS_AlertCode::UnexpectedMessage, true);
        if (packet.recordVersion != m_vsn) throw TLS_Alert(TLS_AlertCode::ProtocolVersion, true);
        std::vector<uint8_t> dataToHash;
        // gross size, the decrypted content size is usually smaller than the encrypted
        dataToHash.reserve(getCSInfo().ci.blockSize ? 13 + packet.realCont.size() : 13);
        stdcopy_to_big_endian(m_seqOther++, std::back_inserter(dataToHash));
        dataToHash.push_back(static_cast<uint8_t>(packet.contTyp));
        stdcopy_to_big_endian(packet.recordVersion, std::back_inserter(dataToHash), 2);
        if (getCSInfo().ci.blockSize) {  // block or stream cipher
            // dont hash the dataToHash vector yet
            // we need to copy the decrypted data to the end of it afterwards
            std::vector<uint8_t> decIV {packet.realCont.begin(),
                                        packet.realCont.begin() + getCSInfo().ci.recordIVLength};
            std::vector<uint8_t> decData {packet.realCont.begin() + getCSInfo().ci.recordIVLength,
                                            packet.realCont.end()};
            auto dec = getCSInfo().ci.dec.bos({getServerWriteKey(), decIV, decData});
            if (getCSInfo().ci.blockSize > 0) {  // block cipher, unpad
                uint8_t padVal = dec.back();
                if (padVal >= dec.size()) throw TLS_Alert(TLS_AlertCode::DecryptError, true);
                dec.resize(dec.size() - (padVal + 1));
            }
            std::vector<uint8_t> mac = {dec.end() - getCSInfo().mi.macKeyLength, dec.end()};
            dec.resize(dec.size() - getCSInfo().mi.macKeyLength);
            stdcopy_to_big_endian(dec.size(), std::back_inserter(dataToHash), 2);
            dataToHash.insert(dataToHash.end(), dec.begin(), dec.end());
            auto hash_ = hmac(getServerWriteMACKey(), dataToHash, getCSInfo().PRFHashInfo);
            if (mac != hash_) {
                Debugging::pu8Vec(dataToHash, 8, true, "MAC mismatch: constructed data to hash");
                Debugging::pu8Vec(hash_, 8, true, "MAC mismatch: expected MAC");
                Debugging::pu8Vec(mac, 8, true, "MAC mismatch: got MAC");
                // throw TLS_Alert(TLS_AlertCode::BadRecordMAC, true);
            }
            return dec;
        } else {  // AEAD cipher
            // TODO: add this as a property of a AEAD cipher
            auto AEADOverhead = 16;
            stdcopy_to_big_endian(packet.realCont.size() - AEADOverhead, std::back_inserter(dataToHash), 2);
            std::vector<uint8_t> decIV {packet.realCont.begin(),
                                        packet.realCont.begin() + getCSInfo().ci.recordIVLength};
            std::vector<uint8_t> decData {packet.realCont.begin() + getCSInfo().ci.recordIVLength,
                                            packet.realCont.end()};
            auto dec = getCSInfo().ci.dec.aead({getServerWriteKey(), decIV, decData, dataToHash, getServerWriteIV()});
            return dec;
        }
    }

    std::vector<uint8_t> TLS_parseAppData(const TLSPlaintext &packet)
    {
        if (packet.contTyp != ContentType::Application)
            throw std::runtime_error("Not an Application packet");
        if (m_state_ != TLS_State_::ServerFinished_)
            throw std::runtime_error("Not in ServerFinished_ state");
        return decPlainText(packet);
    }

    void writeKeyLog(const std::string &path)
    {
        std::ofstream ofs{path, std::ios::app};
        std::ostringstream buf;
        buf << "CLIENT_RANDOM ";
        Debugging::pu8Vec(m_clientRandom, 0, false, "", buf);
        buf << ' ';
        Debugging::pu8Vec(m_masterSecret, 0, false, "", buf);
        buf << '\n';
        std::cout << buf.str();
        ofs << buf.str();
        ofs.close();
    }
};

/* 6.2.  Record Layer
 *
 *    The TLS record layer receives uninterpreted data from higher layers
 *    in non-empty blocks of arbitrary size.
 *
 * 6.2.1.  Fragmentation
 *    The record layer fragments information blocks into TLSPlaintext
 *    records carrying data in chunks of 2^14 bytes or less.  Client
 *    message boundaries are not preserved in the record layer (i.e.,
 *    multiple client messages of the same ContentType MAY be coalesced
 *    into a single TLSPlaintext record, or a single message MAY be
 *    fragmented across several records).
 */
LIBCPPTLS_API
[[nodiscard]] std::list<std::vector<uint8_t>> TLS_composeRecordLayer(const TLSPlaintext &cont)
{
    size_t packetLen_ = cont.realCont.size();
    if (packetLen_ > UINT16_MAX) {
        TLSPlaintext splitContent = cont;
        splitContent.realCont = {cont.realCont.begin(), cont.realCont.begin() + UINT16_MAX};
        auto l0 = TLS_composeRecordLayer(splitContent);
        TLSPlaintext splitContentPart2 = cont;
        splitContentPart2.realCont = {cont.realCont.begin() + UINT16_MAX, cont.realCont.end()};
        auto l = TLS_composeRecordLayer(splitContentPart2);
        l.insert(l.begin(), *l0.begin());
        return l;
    }
    uint16_t packetLen = packetLen_;
    std::vector<uint8_t> TLSmsg;
    TLSmsg.reserve(packetLen + 3);
    TLSmsg.push_back(static_cast<uint8_t>(cont.contTyp));
    stdcopy_to_big_endian(static_cast<uint16_t>(cont.recordVersion), std::back_inserter(TLSmsg));
    stdcopy_to_big_endian(packetLen, std::back_inserter(TLSmsg));
    std::copy(cont.realCont.begin(), cont.realCont.end(), std::back_inserter(TLSmsg));
    return {TLSmsg};
}

struct LIBCPPTLS_API TLS_parseRecordLayerResult_ {
    std::list<TLSPlaintext> parsedContent;
    size_t parsedBytes;
};

LIBCPPTLS_API
TLS_parseRecordLayerResult_ TLS_parseRecordLayer(const std::vector<uint8_t> &packet)
{
    std::cout << "packet of " << packet.size() << " bytes\n";
    auto pSize = packet.size();
    TLS_parseRecordLayerResult_ ret;
    auto parsed = 0;

    while (parsed + 5 <= pSize) {
        auto oldParsed = parsed;
        TLSPlaintext cont;
        cont.contTyp = static_cast<ContentType>(packet[parsed]);
        parsed++;
        if (!validateContentType(cont.contTyp))
            throw TLS_DecodeError("Invalid TLS Record Layer content type");

        cont.recordVersion = from_big_endian<TLS_Version>(packet.data() + parsed);
        parsed += sizeof(cont.recordVersion);

        auto realContSize = from_big_endian<uint16_t>(packet.data() + parsed);
        parsed += sizeof(realContSize);

        if (parsed + realContSize > pSize) {
            parsed = oldParsed;
            break;
        }

        std::copy(packet.data() + parsed, packet.data() + parsed + realContSize,
                  std::back_inserter(cont.realCont));
        parsed += realContSize;
        ret.parsedContent.push_back(cont);
    }

    ret.parsedBytes = parsed;
    return ret;
}

#endif
