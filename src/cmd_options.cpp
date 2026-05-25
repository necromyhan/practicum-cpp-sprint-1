#include "cmd_options.h"

#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Допустимые параметры") {
    desc_.add_options()("help,h", "Справка")("command,c", boost::program_options::value<std::string>()->required(),
                                             "Команды для выполнения: encrypt, decrypt, checksum")(
        "input,i", boost::program_options::value<std::string>()->required(), "Путь до входного файла")(
        "output,o", boost::program_options::value<std::string>(), "Путь до выходного файла (опционально для checksum)")(
        "password,p", boost::program_options::value<std::string>(), "Пароль для шифрования");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        boost::program_options::variables_map vm;

        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);

        if (vm.count("help")) {
            std::cout << desc_ << "\n";
            std::exit(0);
        }

        boost::program_options::notify(vm);

        std::string cmdStr = vm["command"].as<std::string>();
        auto it = commandMapping_.find(cmdStr);
        if (it == commandMapping_.end()) {
            throw std::runtime_error("Недопустимая команда: '" + cmdStr + "'. Доступно: encrypt, decrypt, checksum");
        }
        command_ = it->second;

        inputFile_ = vm["input"].as<std::string>();
        if (vm.count("output")) {
            outputFile_ = vm["output"].as<std::string>();
        }

        if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
            if (!vm.count("password")) {
                throw std::runtime_error("Пароль обязателен для операций шифрования");
            }
            password_ = vm["password"].as<std::string>();
        }

    } catch (const std::exception &e) {
        std::cerr << "Ошибка при чтении параметров: " << e.what() << "\n";
        std::exit(1);
    }
}

}  // namespace CryptoGuard
