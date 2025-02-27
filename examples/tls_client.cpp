#include <arpa/inet.h>
#include <cpptls/crypto/hash/sha256.h>
#include <cpptls/debug.h>
#include <cpptls/tls.h>
#include <cpptls/tls_memory.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <thread>

void *initialize_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    return nullptr;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

const char *keylog_path = "/mnt/c/Users/Admin/Desktop/sslg2.log";

int main()
{
    const char *request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
    const char *hostname = "google.com";
    const int port = 443;

    std::shared_ptr<void> openssl_raii{initialize_openssl(), [](void *) { EVP_cleanup(); }};
    bool hasNetworkConn = true;
    sockaddr_in server_addr;
    {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;        // IPv4
        hints.ai_socktype = SOCK_STREAM;  // TCP

        if (getaddrinfo(hostname, nullptr, &hints, &res) != 0) {
            std::cerr << "Failed to resolve hostname\n";
            return EXIT_FAILURE;
        }
        unique_ptr_with_deleter<void> addrInfoRAII{nullptr, [&](void *) { freeaddrinfo(res); }};

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    }

    try {
        TLS_Session tlss{
            TLS_Version::TLS_1_2,
            {
                CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
                // CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            },
            {
                CompressionMethod::NULL_,
            },
            {
                std::make_unique<TLSExt_ServerName>(hostname),
            },
        };
        auto ch = tlss.TLS_writeClientHello();
        auto res = TLS_composeRecordLayer(ch);
        int socket_;
        {
            Debugging::pu8Vec(ch.realCont, 8, true, "Inner Content");
        }
        auto pRecLayer = [](auto &&res) {
            int i = 0;
            for (auto &&res_record : res) {
                std::cout << "TLS Record Layer " << i++ << ": ";
                Debugging::pu8Vec(res_record);
            }
        };
        pRecLayer(res);
        auto printParsedRecLayer = [](auto &&parsedRecLayer) {
            std::cout << "bytes parsed: " << parsedRecLayer.parsedBytes << '\n';
            if (!parsedRecLayer.parsedBytes) return;
            std::cout << "parsedContent: {\n";
            int i_ = 0;
            for (auto &&cont : parsedRecLayer.parsedContent) {
                std::cout << "content entry " << i_++ << " of type "
                          << static_cast<int>(cont.contTyp)
                          << "(rVer: " << static_cast<int>(cont.recordVersion) << "): [packet of "
                          << cont.realCont.size() << " bytes]\n";
            }
            std::cout << "}\n";
        };

        std::vector<uint8_t> resp;
        bool validSocket = false;
        unique_ptr_with_deleter<void> addrInfoRAII{nullptr, [&](void *) {
                                                       if (validSocket) close(socket_);
                                                   }};
        if (hasNetworkConn) {
            socket_ = socket(AF_INET, SOCK_STREAM, 0);
            if (socket_ < 0) {
                std::cerr << "Socket creation failed\n";
                perror("socket");
                return EXIT_FAILURE;
            }
            if (connect(socket_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                std::cerr << "Connection to server failed\n";
                perror("connect");
                return EXIT_FAILURE;
            }
            validSocket = true;

            for (auto &&recLayerMsg : res) {
                if (send(socket_, recLayerMsg.data(), recLayerMsg.size(), 0) < 0) {
                    std::cerr << "Failed to send request\n";
                    perror("send");
                    return EXIT_FAILURE;
                }
            }

            int bufferSize = 1024;
            std::vector<uint8_t> leftOverResp;
            std::vector<uint8_t> buf_;
            while (tlss.m_state_ != TLS_State_::ServerHelloDone) {
                buf_.resize(bufferSize);
                auto bytes = recv(socket_, buf_.data(), buf_.size(), 0);
                if (bytes <= 0) {
                    std::cerr << "Failed to receive response\n";
                    if (bytes < 0) perror("recv");
                    return EXIT_FAILURE;
                }
                buf_.resize(bytes);
                std::cout << "received " << bytes << " bytes\n" << std::flush;

                if (leftOverResp.size()) {
                    buf_.insert(buf_.begin(), leftOverResp.begin(), leftOverResp.end());
                    leftOverResp.clear();
                }
                auto ret = TLS_parseRecordLayer(buf_);
                printParsedRecLayer(ret);
                if (ret.parsedBytes < bytes) {
                    std::copy(buf_.begin() + ret.parsedBytes, buf_.end(),
                              std::back_inserter(leftOverResp));
                }

                for (auto &&cont : ret.parsedContent) {
                    TLS_AlertError::throwOnAlertPacket(cont, true);
                    if (!tlss.TLS_parseServerHello(cont)) throw 666U;
                }
            }
        } else {
            std::cout << "enter server resp: " << std::flush;
            auto s = Debugging::readTilEOF();
            std::cout << "read " << s.size() << " chars\n";
            resp = Debugging::parseBytesArray(s);

            std::cout << "parsed " << resp.size() << " bytes\n";
            auto ret = TLS_parseRecordLayer(resp);
            printParsedRecLayer(ret);

            for (auto it = ret.parsedContent.begin(), e = ret.parsedContent.end(); it != e; it++) {
                TLS_AlertError::throwOnAlertPacket(*it, true);
                if (!tlss.TLS_parseServerHello(*it)) throw 666U;
            }
        }

        auto kexPackets = tlss.TLS_writeClientKex();
        if (!kexPackets) throw 888.0f;
        tlss.writeKeyLog(keylog_path);
        std::list<std::vector<uint8_t>> recLayerMsgs;
        for (auto &&kexPacket : *kexPackets) {
            auto recLayerMsgList = TLS_composeRecordLayer(kexPacket);
            recLayerMsgs.splice(recLayerMsgs.end(), recLayerMsgList, recLayerMsgList.begin(),
                                recLayerMsgList.end());
        }
        std::cout << "CKexPkts: \n";
        pRecLayer(recLayerMsgs);
        if (hasNetworkConn) {
            std::vector<uint8_t> allKexPackets;
            for (auto &&recLayerMsg : recLayerMsgs)
                allKexPackets.insert(allKexPackets.end(), recLayerMsg.begin(), recLayerMsg.end());
            if (send(socket_, allKexPackets.data(), allKexPackets.size(), 0) < 0) {
                std::cerr << "Failed to send request\n";
                perror("send");
                return EXIT_FAILURE;
            }
            std::cout << "sent " << allKexPackets.size() << " bytes\n";

            {
                int bufferSize = 1024;
                std::vector<uint8_t> leftOverResp;
                std::vector<uint8_t> buf_;
                while (tlss.getState() != TLS_State_::ServerFinished_) {
                    buf_.resize(bufferSize);
                    auto bytes = recv(socket_, buf_.data(), buf_.size(), 0);
                    if (bytes <= 0) {
                        std::cerr << "Failed to receive response or EOF\n";
                        if (bytes < 0) {
                            perror("recv");
                            return EXIT_FAILURE;
                        }
                        std::cerr << "EOF\n";
                        break;
                    }
                    buf_.resize(bytes);
                    std::cout << "received " << bytes << " bytes, accumulated "
                              << leftOverResp.size() << " bytes\n";

                    if (leftOverResp.size()) {
                        buf_.insert(buf_.begin(), leftOverResp.begin(), leftOverResp.end());
                        leftOverResp.clear();
                    }
                    auto ret = TLS_parseRecordLayer(buf_);
                    if (ret.parsedBytes < bytes) {
                        std::copy(buf_.begin() + ret.parsedBytes, buf_.end(),
                                  std::back_inserter(leftOverResp));
                    }
                    printParsedRecLayer(ret);

                    for (auto &&pkt : ret.parsedContent) {
                        TLS_AlertError::throwOnAlertPacket(pkt, true);
                        tlss.TLS_parseServerFinished(pkt);
                    }
                }
            }

            auto reqPacket = TLS_composeRecordLayer(
                *tlss.TLS_writeAppData(Debugging::forceU8ViseArr(std::string_view{request})));
            pRecLayer(reqPacket);
            auto bytes = send(socket_, reqPacket.begin()->data(), reqPacket.begin()->size(), 0);
            if (bytes <= 0) {
                std::cerr << "Failed to send request\n";
                perror("send");
                return EXIT_FAILURE;
            }
            std::cout << "sent " << bytes << " bytes\n";

            {
                int bufferSize = 1024;
                std::vector<uint8_t> leftOverResp;
                std::vector<uint8_t> buf_;
                while (1) {
                    buf_.resize(bufferSize);
                    auto bytes_ = recv(socket_, buf_.data(), buf_.size(), 0);
                    if (bytes_ <= 0) {
                        if (bytes_ < 0) {
                            std::cerr << "Failed to receive response\n";
                            perror("recv");
                            return EXIT_FAILURE;
                        }
                        std::cerr << "EOF\n";
                        break;
                    }
                    buf_.resize(bytes_);
                    std::cout << "received " << bytes_ << " bytes, accumulated "
                              << leftOverResp.size() << " bytes\n";

                    if (leftOverResp.size()) {
                        buf_.insert(buf_.begin(), leftOverResp.begin(), leftOverResp.end());
                        leftOverResp.clear();
                    }
                    auto ret = TLS_parseRecordLayer(buf_);
                    if (ret.parsedBytes < bytes_) {
                        std::copy(buf_.begin() + ret.parsedBytes, buf_.end(),
                                  std::back_inserter(leftOverResp));
                    }
                    printParsedRecLayer(ret);

                    for (auto &&pkt : ret.parsedContent) {
                        TLS_AlertError::throwOnAlertPacket(pkt, true);
                        if (pkt.contTyp == ContentType::Application) {
                            auto res = tlss.TLS_parseAppData(pkt);
                            std::cout << "Decoded AppData: " << std::string{res.begin(), res.end()}
                                      << '\n';
                        }
                    }
                }
            }
        }
        {
            Debugging::pu8Vec(Debugging::forceU8Vise(to_big_endian(tlss.m_state_)), 8, true,
                              "tls session state");
            Debugging::pu8Vec(tlss.m_serverRandom, 8, true, "parsed server random");
            Debugging::pu8Vec(tlss.m_sessionID, 8, true, "parsed session id");
            Debugging::pu8Vec(Debugging::forceU8Vise(to_big_endian(*tlss.m_selectedCipherSuite)), 8,
                              true, "selected cipher suite");
            Debugging::pu8Vec(Debugging::forceU8Vise(*tlss.m_selectedCompressionMethod), 8, true,
                              "m_selectedCompressionMethod");
            Debugging::pu8Vec(tlss.m_serverPubKey, 8, true, "server pubkey");
            Debugging::pu8Vec(tlss.m_preMasterSecret, 8, true, "pre-master secret");
            Debugging::pu8Vec(tlss.m_masterSecret, 8, true, "master secret");
            Debugging::pu8Vec(tlss.getKeyBlock(), 8, true, "keyblock");
        }
    } catch (std::exception &e) {
        std::cerr << "what(): " << e.what() << '\n';
    } catch (...) {
        std::cerr << "Unknown exception\n";
    }
    if (!hasNetworkConn || false) return EXIT_FAILURE;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    unique_ptr_with_deleter<int> sock_ptr{&sock, [](int *s) { ::close(*s); }};
    if (sock < 0) {
        std::cerr << "Socket creation failed\n";
        perror("socket");
        return EXIT_FAILURE;
    }
    std::cout << "socket creation\n";

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection to server failed\n";
        perror("connect");
        return EXIT_FAILURE;
    }
    std::cout << "post-connect\n";

    unique_ptr_with_deleter<SSL_CTX> ctx{create_context(), SSL_CTX_free};

    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_2_VERSION) != 1) {
        std::cerr << "Failed to set TLS version to TLSv1.2\n";
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    SSL_CTX_set_keylog_callback(ctx.get(), [](const SSL *ssl_, const char *line) {
        using namespace std::string_literals;
        std::ostringstream oss;
        oss << line << '\n';
        std::ofstream ofs{keylog_path, std::ios::app};
        ofs << oss.str();
        ofs.close();
        std::cout << oss.str();
        std::string ln = line;
        if (ln.substr(0, ln.find(' ')) == "CLIENT_RANDOM"s) {
            ln = ln.substr(ln.rfind(' ') + 1);
            std::cout << "OSSL MASTER SECRET SHOULD BE " << ln << '\n';
            std::vector<uint8_t> seed(64);
            SSL_get_server_random(ssl_, seed.data(), 32);
            SSL_get_client_random(ssl_, seed.data() + 32, 32);
            auto kblock = TLS_PRF(Debugging::parseBytesArray(ln), "key expansion"s, seed, 104,
                                  HashAlgo_SHA256::hi);
            Debugging::pu8Vec(kblock, 8, true, "kblock");
            std::vector<uint8_t> cwkey{kblock.data() + 64, kblock.data() + 80};
            Debugging::pu8Vec(cwkey, 8, true, "cwkey");
            std::cout << "cwkey(c): " << Debugging::genCStyleArray(cwkey) << '\n';
            std::vector<uint8_t> cwiv{kblock.data() + 96, kblock.data() + 100};
            Debugging::pu8Vec(cwiv, 8, true, "cwiv");
            std::cout << "cwiv(c): " << Debugging::genCStyleArray(cwiv) << '\n';
        }
    });
    SSL_CTX_set_cipher_list(ctx.get(), "AES128-GCM-SHA256");

    unique_ptr_with_deleter<SSL> ssl{SSL_new(ctx.get()), [](SSL *ssl_) {
                                         if (ssl_) SSL_free(ssl_);
                                     }};
    if (!ssl) {
        std::cerr << "SSL creation failed\n";
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    // Bind SSL to the socket
    SSL_set_fd(ssl.get(), sock);

    // Perform SSL handshake
    if (SSL_connect(ssl.get()) <= 0) {
        std::cerr << "SSL handshake failed\n";
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    unique_ptr_with_deleter<void> u{nullptr, [&](void *) { SSL_shutdown(ssl.get()); }};
    std::cout << "ssl conn\n";

    unique_ptr_with_deleter<X509> cert{SSL_get_peer_certificate(ssl.get()), X509_free};
    if (cert) {
        char *line = X509_NAME_oneline(X509_get_subject_name(cert.get()), nullptr, 0);
        std::cout << "Server Certificate: " << line << std::endl;
        OPENSSL_free(line);
    } else {
        std::cerr << "No certificate provided by server\n";
        return EXIT_FAILURE;
    }

    // Send GET request
    if (SSL_write(ssl.get(), request, strlen(request)) <= 0) {
        std::cerr << "Failed to send request\n";
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    std::cout << "ssl write: " << request << '\n';

    // Read and print the response
    char buffer[4096];
    int bytes_read;
    while ((bytes_read = SSL_read(ssl.get(), buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';  // Null-terminate the buffer
        std::cout << buffer;
    }
    std::cout << "ssl read\n";

    if (bytes_read < 0) {
        std::cerr << "Error reading response\n";
        ERR_print_errors_fp(stderr);
    }

    std::cout << "ssl shutdown\n";

    return 0;
}
