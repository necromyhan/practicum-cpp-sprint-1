#include "crypto_guard_ctx.h"
#include <array>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <vector>

namespace CryptoGuard {

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const {
        if (ctx)
            EVP_CIPHER_CTX_free(ctx);
    }
};

using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::PImpl {
public:
    PImpl() { OpenSSL_add_all_algorithms(); }

    ~PImpl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        CheckStreams(inStream, outStream);

        AesCipherParams params = CreateCipherParamsFromPassword(password);
        params.encrypt = 1;

        EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) {
            throw std::runtime_error("Не удалось создать EVP_CIPHER_CTX");
        }

        if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) !=
            1) {
            throw std::runtime_error("Не удалось инициализировать cipher");
        }

        ProcessCipher(inStream, outStream, ctx.get());
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:
    void CheckStreams(const std::iostream &in, const std::iostream &out) {
        if (!in)
            throw std::runtime_error("Не валидный входной поток");
        if (!out)
            throw std::runtime_error("Не валидный выходной поток");
    }

    void ProcessCipher(std::iostream &inStream, std::iostream &outStream, EVP_CIPHER_CTX *ctx) {
        std::vector<unsigned char> inBuffer(4096);
        std::vector<unsigned char> outBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
        int outLen = 0;

        // Цикл обработки блоков с проверкой состояния потоков
        while (inStream.read(reinterpret_cast<char *>(inBuffer.data()), inBuffer.size()) || inStream.gcount() > 0) {
            if (inStream.bad()) {
                throw std::runtime_error("Не валидный входной поток");
            }

            // Использование универсального EVP_CipherUpdate в соответствии с примером
            if (EVP_CipherUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(),
                                 static_cast<int>(inStream.gcount())) != 1) {
                throw std::runtime_error("Ошибка функции Update");
            }

            if (outLen > 0) {
                outStream.write(reinterpret_cast<const char *>(outBuffer.data()), outLen);
                if (!outStream) {
                    throw std::runtime_error("Не валидный выходной поток");
                }
            }
        }

        // Финализация работы в соответствии с примером
        if (EVP_CipherFinal_ex(ctx, outBuffer.data(), &outLen) != 1) {
            throw std::runtime_error("Ошибка функции Final");
        }

        if (outLen > 0) {
            outStream.write(reinterpret_cast<const char *>(outBuffer.data()), outLen);
            if (!outStream) {
                throw std::runtime_error("Не валидный выходной поток");
            }
        }
    }

    AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<PImpl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard