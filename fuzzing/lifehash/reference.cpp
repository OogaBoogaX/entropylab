// Line-oriented driver for Blockchain Commons' C++ LifeHash reference
// (bc-lifehash), used by fuzzing/lifehash/fuzz-cpp.mjs as the oracle.
//
// Each stdin line is "<hex data> <module size>". The reply is one stdout line:
// the hex RGB bytes of make_from_data(data, version2, module_size, false), or
// "error <message>" if the reference throws. Built and run by the fuzzer only;
// nothing here is part of the app.
#include <iostream>
#include <sstream>
#include <string>

#include "lifehash.hpp"

int main() {
    std::ios::sync_with_stdio(false);
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream fields(line);
        std::string hex;
        size_t module_size = 0;
        if (!(fields >> hex >> module_size) || module_size == 0) {
            std::cout << "error malformed request" << std::endl;
            continue;
        }
        try {
            auto image = LifeHash::make_from_data(LifeHash::hex_to_data(hex), LifeHash::Version::version2, module_size, false);
            std::cout << image.width << " " << image.height << " " << LifeHash::data_to_hex(image.colors) << std::endl;
        } catch (const std::exception& e) {
            std::cout << "error " << e.what() << std::endl;
        }
    }
    return 0;
}
