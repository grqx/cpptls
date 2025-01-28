#ifndef TLS_CLIENT_TLS_CERT_H
#define TLS_CLIENT_TLS_CERT_H

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <vector>
#include <iostream>
#include <memory>
#include <cstring>

// chatgpt-written code, plan rewrite for reliability
namespace ChatGPT4o {
#define TLS_CLIENT_MAY_BE_UNSTABLE
struct X509Deleter {
    void operator()(X509* x) const { X509_free(x); }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

std::vector<uint8_t> encRSA(const std::vector<uint8_t>& cont, const EVP_PKEY_Ptr& pubKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey.get(), nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialise encryption context");
    }

    // Determine buffer size needed for encryption
    size_t outLen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, cont.data(), cont.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to determine encryption buffer size");
    }

    // Encrypt the data
    std::vector<uint8_t> encryptedData(outLen);
    if (EVP_PKEY_encrypt(ctx, encryptedData.data(), &outLen, cont.data(), cont.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }

    EVP_PKEY_CTX_free(ctx);
    encryptedData.resize(outLen); // Adjust the vector size to the actual output
    return encryptedData;
}


std::vector<uint8_t> serializePublicKey(const EVP_PKEY_Ptr& pubKey) {
    std::vector<uint8_t> keyData;
    int len = i2d_PUBKEY(pubKey.get(), nullptr); // Get the required length
    if (len <= 0) {
        throw std::runtime_error("Failed to determine public key length: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
    keyData.resize(len);

    uint8_t* p = keyData.data();
    if (i2d_PUBKEY(pubKey.get(), &p) <= 0) { // Serialise to DER
        throw std::runtime_error("Failed to serialize public key: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    return keyData;
}

EVP_PKEY_Ptr deserializePublicKey(const std::vector<uint8_t>& keyData) {
    const uint8_t* p = keyData.data();
    EVP_PKEY* pubKey = d2i_PUBKEY(nullptr, &p, static_cast<long>(keyData.size()));
    if (!pubKey) {
        throw std::runtime_error("Failed to deserialize public key: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
    return EVP_PKEY_Ptr(pubKey);
}

std::vector<X509Ptr> parseCertificates(const std::vector<uint8_t>& certChain) {
    std::vector<X509Ptr> certificates;
    const uint8_t* ptr = certChain.data();
    const uint8_t* end = ptr + certChain.size();

    while (ptr + 3 <= end) { // Ensure there's enough data for the length field
        // Read the length of the next certificate (3 bytes big-endian)
        uint32_t certLen = (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
        ptr += 3;

        if (ptr + certLen > end) { // Check for data overflow
            throw std::runtime_error("Malformed certificate chain: certificate length exceeds available data");
        }

        // Parse the certificate
        const uint8_t* certStart = ptr;
        X509* cert = d2i_X509(nullptr, &certStart, certLen);
        if (!cert) {
            throw std::runtime_error("Failed to parse certificate: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        certificates.emplace_back(cert);

        ptr += certLen; // Move to the next certificate
    }

    return certificates;
}

EVP_PKEY_Ptr getPublicKeyFromCertificate(const X509Ptr& cert) {
    EVP_PKEY* pubKey = X509_get_pubkey(cert.get());
    if (!pubKey) {
        throw std::runtime_error("Failed to extract public key from certificate: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
    return EVP_PKEY_Ptr(pubKey);
}

[[nodiscard]] std::vector<uint8_t> getPubKey(const std::vector<uint8_t>& certChain) {
    EVP_PKEY_Ptr serverPubKey;
    try {
        // Parse certificates (assumes certChain contains concatenated DER certificates)
        auto certificates = parseCertificates(certChain);
        if (certificates.empty()) {
            throw std::runtime_error("No certificates found in chain");
        }

        serverPubKey = getPublicKeyFromCertificate(certificates.front());

        for (const auto& cert : certificates) {
            char* subj = X509_NAME_oneline(X509_get_subject_name(cert.get()), nullptr, 0);
            char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert.get()), nullptr, 0);
            if (subj && issuer) {
                std::cout << "Certificate Subject: " << subj << "\n";
                std::cout << "Certificate Issuer: " << issuer << "\n";
            }
            OPENSSL_free(subj);
            OPENSSL_free(issuer);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return {};
    }

    return {serializePublicKey(serverPubKey)};
}

};  // namespace ChatGPT4o

#endif
