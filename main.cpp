#include <iostream>
#include <cstdlib>
#include <string>
#include <sstream>
#include <unordered_map>
#include <array>

// Доверенные IP и MAC
std::unordered_map<std::string, std::string> trustedDevices = {
    {"192.168.1.2", "00:1A:2B:3C:4D:5E"},
    {"192.168.1.3", "00:1A:2B:3C:4D:5F"}
};

void checkArpTable() {
    std::array<char, 128> buffer;
    std::string result;

    // Получаем ARP-таблицу
    FILE* pipe = popen("arp -n", "r");
    if (!pipe) {
        std::cerr << "Не удалось открыть конвейер." << std::endl;
        return;
    }

 // Доверенные IP и MAC
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);
    
    //Вывод ARP таблицы
    std::cout << "ARP таблица:\n" << result << std::endl;

    // Анализ ARP-таблицы
    std::istringstream ss(result);
    std::string line;
    while (std::getline(ss, line)) {
        std::istringstream iss(line);
        std::string ip, hwAddr;

        if (iss >> ip >> std::ws && (iss >> hwAddr)) { // Считываем только IP и MAC
            // Проверка против доверенного списка
            if (trustedDevices.count(ip) && trustedDevices[ip] != hwAddr) {
                std::cout << "Подозрительная запись: IP=" << ip 
                          << ", ожидаемый MAC=" << trustedDevices[ip] 
                          << ", фактический MAC=" << hwAddr << std::endl;
            }
        }
    }
}

int main() {
    std::cout << "Проверка ARP-таблицы..." << std::endl;
    checkArpTable();
    return 0;
}
