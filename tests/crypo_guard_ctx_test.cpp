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

// Decrypt. Правильное шифрование и дешифрование
TEST(CryptoGuardDecryptTest, EncryptAndDecryptValid) {
    CryptoGuard::CryptoGuardCtx guard;
    std::string secret = "Yandex Practicum Middle Cpp";
    std::stringstream in(secret);
    std::stringstream cipherStream;
    std::stringstream plainStream;
    std::string pass = "Password";

    guard.EncryptFile(in, cipherStream, pass);
    ASSERT_NO_THROW(guard.DecryptFile(cipherStream, plainStream, pass));
    ASSERT_EQ(plainStream.str(), secret);
}

// Decrypt. Неверный пароль
TEST(CryptoGuardDecryptTest, BadPassword) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream in("Yandex Practicum Middle Cpp");
    std::stringstream cipherStream;
    std::stringstream plainStream;

    guard.EncryptFile(in, cipherStream, "CorrectPassword");
    ASSERT_THROW(guard.DecryptFile(cipherStream, plainStream, "WrongPassword"), std::runtime_error);
}

// Decrypt. Поврежденный зашифрованный блок данных
TEST(CryptoGuardDecryptTest, ThrowsOnCorruptedCiphertext) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream in("Data Block");
    std::stringstream cipherStream;
    std::stringstream plainStream;

    guard.EncryptFile(in, cipherStream, "Password");

    std::string corruptedData = cipherStream.str();
    if (!corruptedData.empty()) {
        corruptedData[1] ^= 0xFF;  // Меняем бит в зашифрованных данных
    }
    std::stringstream corruptedStream(corruptedData);

    ASSERT_THROW(guard.DecryptFile(corruptedStream, plainStream, "Password"), std::runtime_error);
}

// Checksum. Валидный подсчет
TEST(CryptoGuardChecksumTest, ChecksumValidSha256) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream in("abc");

    std::string checksum = guard.CalculateChecksum(in);
    ASSERT_EQ(checksum, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// Checksum. Валидный подсчет пустой строки
TEST(CryptoGuardChecksumTest, EmptyStringChecksum) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream in("");

    std::string checksum = guard.CalculateChecksum(in);
    ASSERT_EQ(checksum, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}