#include <gtest/gtest.h>
#include <sstream>

#include "crypto_guard_ctx.h"

// Ecnrypt. Правильное шифрование
TEST(CryptoGuardEncryptTest, EncryptValidData) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream in("Yandex Practicum Middle Cpp");
    std::stringstream out;

    ASSERT_NO_THROW(guard.EncryptFile(in, out, "Password"));
    ASSERT_FALSE(out.str().empty());
    ASSERT_NE(out.str(), in.str());
}

// Ecnrypt. Правильное шифрование пустого потока
TEST(CryptoGuardEncryptTest, EncryptEmptyDataSuccessfully) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream in("");
    std::stringstream out;

    ASSERT_NO_THROW(guard.EncryptFile(in, out, "Password"));
    // Блочный шифр создает один полный блок паддинга (16 байт) для пустых данных
    ASSERT_EQ(out.str().size(), 16);
}

// Ecnrypt. Невалидный входной поток
TEST(CryptoGuardEncryptTest, BadInputStream) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream in;
    // Имитируем критический сбой потока
    in.setstate(std::ios::badbit);
    std::stringstream out;

    ASSERT_THROW(guard.EncryptFile(in, out, "Password"), std::runtime_error);
}