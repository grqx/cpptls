#ifndef TLS_CLIENT_TLS_TYPES_H
#define TLS_CLIENT_TLS_TYPES_H

#include <vector>
#include <cstdint>
#include <optional>
#include <string>
#include <functional>
#include <stdexcept>

#include "endian_utils.h"

namespace CipherSpecChangedFlag {
constexpr uint8_t clientChanged = 0x01;
constexpr uint8_t serverChanged = 0x02;
};  // namespace CipherSpecChangedFlag

enum class TLS_Version : uint16_t {
    TLS_1_2 = 0x0303,
    TLS_1_3 = 0x0304,
};

// Each cipher suite defines a key
//    exchange algorithm, a bulk encryption algorithm (including secret key
//    length), a MAC algorithm, and a PRF
enum class CipherSuite : uint16_t {
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f
};



typedef struct {
    const std::vector<uint8_t>& secret;
    const std::vector<uint8_t>& msg;
} HMAC_hashFnArgsType;

// HMAC hash function type
// returns the HMAC hash
typedef std::function<std::vector<uint8_t>(HMAC_hashFnArgsType)> HMAC_hashFnType;

typedef struct {
    const std::vector<uint8_t>& key;
    const std::vector<uint8_t>& iv;
    const std::vector<uint8_t>& data;
} symEncFnArgsType;
typedef std::function<std::vector<uint8_t>(symEncFnArgsType)> symEncFnType;

typedef struct {
    const std::vector<uint8_t>& key;
    const std::vector<uint8_t>& iv;
    const std::vector<uint8_t>& encryptedData;
} symDecFnArgsType;
typedef std::function<std::vector<uint8_t>(symDecFnArgsType)> symDecFnType;

enum class CompressionMethod : uint8_t {
    NULL_ = 0x00
};

enum class ContentType : uint8_t {
    ChangeCipherSpec = 0x14,
    Alert = 0x15,
    Handshake = 0x16,
    Application = 0x17,
    Heartbeat = 0x18
};

inline bool validateContentType(ContentType ct)
{
    return ContentType::ChangeCipherSpec <= ct  && ct <= ContentType::Heartbeat;
}

struct TLSPlaintext {
    std::vector<uint8_t> realCont;
    ContentType contTyp;
    TLS_Version recordVersion;
};

enum class HandshakeType : uint16_t {
    ClientHello = 0x01,
    ServerHello = 0x02,
    NewSessTicket = 0x04,
    Certificate = 0x0b,
    ServerKex = 0x0c,
    ServerDn = 0x0e,
    ClientKex = 0x10,
    Finished = 0x14
};

// TODO
inline bool validateHandshakeType(HandshakeType ht)
{
    return true;
}

// length of a minimum TLS handshake protocol TLSInnerText, i.e. 0xXX00 0000
constexpr auto MIN_HANDSHAKE_PACKET_LEN = 4;


class TLS_Handshake final {
public:
    HandshakeType m_ht;
    std::vector<uint8_t> m_cont;

    TLSPlaintext toPacket(TLS_Version vsn) const
    {
        TLSPlaintext ret;
        ret.contTyp = ContentType::Handshake;
        ret.recordVersion = vsn;
        ret.realCont.push_back(static_cast<uint8_t>(m_ht));
        if (m_cont.size() > UINT24_MAX) throw std::overflow_error("Handshake content length overflowed UINT24_MAX");
        stdcopy_to_big_endian(static_cast<uint32_t>(m_cont.size()), std::back_inserter(ret.realCont), 3);
        std::copy(m_cont.begin(), m_cont.end(), std::back_inserter(ret.realCont));
        return ret;
    }

    static std::optional<TLS_Handshake> parse(TLSPlaintext tpt, bool lazy = false)
    {
        if (tpt.contTyp != ContentType::Handshake) return std::nullopt;
        auto tptSize = tpt.realCont.size();
        if (tptSize < MIN_HANDSHAKE_PACKET_LEN) return std::nullopt;
        TLS_Handshake hs;
        hs.m_ht = static_cast<HandshakeType>(tpt.realCont[0]);
        if (!validateHandshakeType(hs.m_ht)) return std::nullopt;
        auto contLen = from_big_endian<uint32_t, 3>(tpt.realCont.data() + 1);
        if (tptSize < MIN_HANDSHAKE_PACKET_LEN + contLen) return std::nullopt;
        auto itBegin = tpt.realCont.begin() + MIN_HANDSHAKE_PACKET_LEN;
        if (lazy)
            hs.m_cont = {itBegin, itBegin + contLen};
        else
            std::copy(itBegin, itBegin + contLen, std::back_inserter(hs.m_cont));
        return hs;
    }
};

enum class TLS_AlertCode : uint8_t {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMAC = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    NoCertificate = 41,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCA = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestriction = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    NoRenegotiation = 100,
    UnsupportedExtension = 110,
    CertificateUnobtainable = 111,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    BadCertificateHashValue = 114,
    UnknownPSKIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
    NoApplicationProtocol_ = 255
};

static std::optional<std::string> strAlertDesc(uint8_t desc)
{
    switch(desc)
    {
    case 0:
        return "Close notify";
    case 10:
        return "Unexpected message";
    case 20:
        return "Bad record MAC";
    case 21:
        return "Decryption failed";
    case 22:
        return "Record overflow";
    case 30:
        return "Decompression failure";
    case 40:
        return "Handshake failure";
    case 41:
        return "No certificate";
    case 42:
        return "Bad certificate";
    case 43:
        return "Unsupported certificate";
    case 44:
        return "Certificate revoked";
    case 45:
        return "Certificate expired";
    case 46:
        return "Certificate unknown";
    case 47:
        return "Illegal parameter";
    case 48:
        return "Unknown CA (Certificate authority)";
    case 49:
        return "Access denied";
    case 50:
        return "Decode error";
    case 51:
        return "Decrypt error";
    case 60:
        return "Export restriction";
    case 70:
        return "Protocol version";
    case 71:
        return "Insufficient security";
    case 80:
        return "Internal error";
    case 86:
        return "Inappropriate fallback";
    case 90:
        return "User canceled";
    case 100:
        return "No renegotiation";
    case 110:
        return "Unsupported extension";
    case 111:
        return "Certificate unobtainable";
    case 112:
        return "Unrecognized name";
    case 113:
        return "Bad certificate status response";
    case 114:
        return "Bad certificate hash value";
    case 115:
        return "Unknown PSK identity (used in TLS-PSK and TLS-SRP)";
    case 116:
        return "Certificate required";
    case 120:
    case 255:
        return "No application protocol";
    default:
        return std::nullopt;
    }
}

enum class TLS_AlertLevel : uint8_t {
    Warning = 0x01,
    Fatal = 0x02
};

// internal enum class to keep track of the connection state
// may need to be changed when upgrading to TLS v1.3
enum class TLS_State_ {
    Created,
    ClientHelloDone,
    ServerHelloDone,
    KexDone,
    ClientFinished_,
    // TODO: parse server finished and server change cipher spec
    ServerFinished_,
    Terminated,
    Error
};

class TLS_Alert final : public std::exception {
private:
    TLS_AlertCode m_aCode;
    bool m_fatal;
    mutable std::optional<std::string> desc;
public:
    TLS_Alert(TLS_AlertCode aCode, bool fatal) : m_aCode(aCode), m_fatal(fatal) {}
    TLS_Alert(TLS_AlertCode aCode, TLS_AlertLevel lvl) : m_aCode(aCode), m_fatal(lvl == TLS_AlertLevel::Fatal) {}
    TLSPlaintext toPacket(TLS_Version vsn)
    {
        TLSPlaintext ret;
        ret.contTyp = ContentType::Alert;
        ret.recordVersion = vsn;
        ret.realCont = {static_cast<uint8_t>(m_aCode), static_cast<uint8_t>(m_fatal ? TLS_AlertLevel::Fatal : TLS_AlertLevel::Warning)};
        return ret;
    }
    const char* what() const noexcept
    {
        if (desc) return desc->c_str();
        desc.emplace(strAlertDesc(static_cast<uint8_t>(m_aCode)).value_or("<Unknown TLS Alert>"));
        return desc->c_str();
    }
};

class TLS_Session;

#endif
