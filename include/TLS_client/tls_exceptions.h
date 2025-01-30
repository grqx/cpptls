#ifndef TLS_CLIENT_TLS_EXCEPTIONS_H
#define TLS_CLIENT_TLS_EXCEPTIONS_H

#include <optional>
#include <stdexcept>

#include "tls_types.h"

// base class for various tls errors
class TLS_BaseError : public std::runtime_error
{
   public:
    TLS_BaseError(const std::string &s = "TLS error") : runtime_error(s) {}
    virtual std::optional<TLS_Alert> toAlert() const noexcept
    {
        return std::nullopt;
    }
    std::optional<TLSPlaintext> toAlertPacket(TLS_Version vsn) const noexcept
    {
        auto al = toAlert();
        if (!al) return std::nullopt;
        return al->toPacket(vsn);
    }
    virtual ~TLS_BaseError() = default;
};

class TLS_DecodeError : public TLS_BaseError
{
   public:
    template <typename... Args>
    TLS_DecodeError(Args &&...args) : TLS_BaseError(std::forward<decltype(args)...>(args...))
    {
    }
    std::optional<TLS_Alert> toAlert() const noexcept override
    {
        return TLS_Alert(TLS_AlertCode::DecodeError, TLS_AlertLevel::Fatal);
    }
};

// throw on received alert
class TLS_AlertError : public TLS_BaseError
{
   private:
    template <typename... Args>
    TLS_AlertError(Args &&...args) : TLS_BaseError(std::forward<decltype(args)...>(args...))
    {
    }
    std::optional<TLS_Alert> toAlert() const noexcept override
    {
        return std::nullopt;
    }

   public:
    TLS_AlertError(uint8_t code) : TLS_BaseError(strAlertDesc(code).value_or("<Unknown TLS Alert>"))
    {
    }

    static std::optional<TLS_AlertError> fromPacket(const TLSPlaintext &content, bool returnWarning)
    {
        if (content.contTyp != ContentType::Alert) return std::nullopt;
        if (content.realCont.size() != 2) return std::nullopt;
        uint8_t lvl = content.realCont[0];
        bool isWarning = lvl == 1;
        if (!isWarning && lvl != 2) return std::nullopt;
        if (isWarning && !returnWarning) return std::nullopt;
        auto str = strAlertDesc(content.realCont[1]);
        if (!str) return std::nullopt;
        return TLS_AlertError(*str);
    }

    static void throwOnAlertPacket(const TLSPlaintext &content, bool throwWarning = false)
    {
        auto alert = fromPacket(content, throwWarning);
        if (alert) throw *alert;
    }
};

class TLS_NotImplemented : public TLS_BaseError
{
   public:
    template <typename... Args>
    TLS_NotImplemented(Args &&...args) : TLS_BaseError(std::forward<decltype(args)...>(args...))
    {
    }
    TLS_NotImplemented() : TLS_BaseError() {}
    std::optional<TLS_Alert> toAlert() const noexcept override
    {
        return TLS_Alert(TLS_AlertCode::InternalError, TLS_AlertLevel::Fatal);
    }
};

#endif
