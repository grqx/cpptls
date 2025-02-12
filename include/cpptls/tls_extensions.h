#ifndef LIBCPPTLS_TLS_EXTENSIONS_H
#define LIBCPPTLS_TLS_EXTENSIONS_H

#include <cpptls/export.h>
#include <cpptls/endian_utils.h>
#include <cpptls/macros.h>

#include <vector>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <string_view>

class LIBCPPTLS_API TLS_Extension {
protected:
    // this is to be set by subclasses when initialising TLS_Extension class
    uint16_t m_extensionType = 0x0000;
    constexpr TLS_Extension(const uint16_t &extensionType) : m_extensionType(extensionType) {}
    virtual int serialiseExtension(uint8_t *buf = nullptr) const noexcept = 0;
public:
    virtual ~TLS_Extension() = default;
    /*
     * Serialise the extension into the buffer.
     * Call with nullptr to get the length.
     * Returns the length of the serialised extension
     * or:
     *  -1 if the extension is too large
     *  the return value of serialiseExtension if less than 0
     */
    int serialiseInto(uint8_t *buf = nullptr) const noexcept {
        if (!buf)
            return 4 + serialiseExtension();
        auto s = serialiseExtension();
        if (s < 0)
            return s;
        copy_to_ptr_big_endian(m_extensionType, buf);
        if (s > UINT16_MAX)
            return -1;
        copy_to_ptr_big_endian(s, buf + 2, 2);
        s = serialiseExtension(buf + 4);
        return s < 0 ? s : 4 + s;
    }
};

class LIBCPPTLS_API TLSExt_ServerName : public TLS_Extension {
public:
    constexpr static uint16_t extensionType = 0x0000;
    enum class NameType : uint8_t {
        host_name = 0,
    };
    struct ServerName {
        NameType nameType;
        // this should be serialised
        std::vector<uint8_t> name;
    };
    TLSExt_ServerName(const std::vector<ServerName> &serverNames) : TLS_Extension(extensionType), m_serverNames(serverNames) {}
    TLSExt_ServerName(std::string_view sv) : TLS_Extension(extensionType), m_serverNames({{NameType::host_name, {sv.begin(), sv.end()}}}) {}
private:
    std::vector<ServerName> m_serverNames;
    int serialiseExtension(uint8_t *buf = nullptr) const noexcept override {
        if (!buf) {
            size_t cnt = 2;  // server name list length
            for (auto &&sn : m_serverNames)
                cnt += 1 + 2 + sn.name.size();
            return cnt;
        }
        uintptr_t offset = 2;
        for (auto &&sn : m_serverNames) {
            buf[offset++] = UNDERLYING(sn.nameType);
            if (sn.name.size() > UINT16_MAX)  // server name serialisation overflow
                return -2;
            copy_to_ptr_big_endian(sn.name.size(), buf + offset, 2);
            offset += 2;
            std::copy(sn.name.begin(), sn.name.end(), buf + offset);
            offset += sn.name.size();
        }
        copy_to_ptr_big_endian(offset - 2, buf, 2);
        return offset;
    }
};

class LIBCPPTLS_API TLSExt_SupportedVersions : public TLS_Extension {
private:
    std::vector<TLS_Version> m_vsns;
    int serialiseExtension(uint8_t *buf = nullptr) const noexcept override {
        auto size = m_vsns.size() * sizeof(TLS_Version);
        if (!buf)
            return 1 + size;
        if (size > UINT8_MAX)
            return -2;
        *(buf++) = size;
        for (auto &&vsn : m_vsns) {
            copy_to_ptr_big_endian(vsn, buf, sizeof(TLS_Version));
            buf += sizeof(TLS_Version);
        }
        return 1 + size;
    }
public:
    constexpr static uint16_t extensionType = 0x0000;
    TLSExt_SupportedVersions(const std::vector<TLS_Version> &vsns) : TLS_Extension(extensionType), m_vsns(vsns) {}
    TLSExt_SupportedVersions(const TLS_Version &vsns) : TLS_Extension(extensionType), m_vsns({vsns}) {}
};

#endif
