#include "cmd_options.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace CryptoGuard;

// Вспомогательная функция для генерации argv (имитация командной строки)
std::vector<char *> MakeArgv(const std::vector<std::string> &args) {
    static std::vector<std::string> holder;
    holder = args;
    std::vector<char *> argv;
    for (auto &s : holder) {
        argv.push_back(const_cast<char *>(s.c_str()));
    }
    argv.push_back(nullptr);
    return argv;
}

// Успешная команда encrypt
TEST(ProgramOptions, EncryptValidOptions) {
    ProgramOptions options;
    auto argv = MakeArgv({"app", "-c", "encrypt", "-i", "in.txt", "-o", "out.txt", "-p", "1234"});

    // Метод не должен вызывать exit, так как параметры валидныЦ
    options.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "in.txt");
    EXPECT_EQ(options.GetOutputFile(), "out.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

// Успешная команда checksum
TEST(ProgramOptions, ChecksumValidOptions) {
    ProgramOptions options;
    auto argv = MakeArgv({"app", "--command", "checksum", "--input", "file.dat"});

    options.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "file.dat");
    EXPECT_EQ(options.GetOutputFile(), "");
    EXPECT_EQ(options.GetPassword(), "");
}

// Успешная команда help
TEST(ProgramOptions, HelpFlagExitsSuccessfully) {
    ProgramOptions options;
    auto argv = MakeArgv({"app", "--help"});

    // Флаг help должен выводить справку и завершать процесс с кодом 0
    // Перенаправляем cout в cerr внутри запущенного процесса теста, чтобы GTest смог перехватить регулярное выражение
    ASSERT_EXIT(
        {
            std::cout.rdbuf(std::cerr.rdbuf());
            options.Parse(static_cast<int>(argv.size()) - 1, argv.data());
        },
        ::testing::ExitedWithCode(0), "Команды для выполнения");
}

// Ошибка при вводе неизвестной команды
TEST(ProgramOptions, InvalidCommandName) {
    ProgramOptions options;
    auto argv = MakeArgv({"app", "-c", "unknown_cmd", "-i", "test.txt"});

    ASSERT_EXIT(options.Parse(static_cast<int>(argv.size()) - 1, argv.data()), ::testing::ExitedWithCode(1),
                "Недопустимая команда");
}

// Ошибка при отсутствии обязательных параметров
TEST(ProgramOptions, MissingRequiredInput) {
    ProgramOptions options;
    auto argv = MakeArgv({"app", "-c", "checksum"});

    ASSERT_EXIT(options.Parse(static_cast<int>(argv.size()) - 1, argv.data()), ::testing::ExitedWithCode(1),
                "Ошибка при чтении параметров:");
}

// Ошибка при отсутствии пароля для команды decrypt
TEST(ProgramOptions, DecryptMissingPassword) {
    ProgramOptions options;
    auto argv = MakeArgv({"app", "-c", "decrypt", "-i", "in.enc", "-o", "out.txt"});

    ASSERT_EXIT(options.Parse(static_cast<int>(argv.size()) - 1, argv.data()), ::testing::ExitedWithCode(1),
                "Пароль обязателен");
}
