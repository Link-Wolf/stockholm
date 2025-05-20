/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   stockholm.cpp                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: xxxxxxx <xxxxxxx@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/14 13:52:07 by xxxxxxx           #+#    #+#             */
/*   Updated: 2023/09/14 13:52:08 by xxxxxxx          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../incs/stockholm.hpp"

int	main(int argc, char **argv) {
	std::string ip_address = "";
	uint port = -1;
	bool connection_based = false;
	Stockholm stockholm;

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--connected") == 0 || strcmp(argv[i], "-c") == 0) { // With connection based
			std::cout << "Connected mode activated" << std::endl;
			connection_based = true;
		}
		else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			ip_address = argv[++i];
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			std::string port_str = argv[++i];
			if (!std::all_of(port_str.begin(), port_str.end(), ::isdigit)) {
				std::cerr << "Error: Port must be a numeric value" << std::endl;
				return -1;
			}
			try {
				port = std::stoi(port_str);
				if (port < 0 || port > 65535) {
					throw std::out_of_range("Port out of range");
				}
			} catch (const std::invalid_argument& e) {
				std::cerr << "Error: Invalid port number" << std::endl;
				return -1;
			} catch (const std::out_of_range& e) {
				std::cerr << "Error: Port number out of range" << std::endl;
				return -1;
			}
		}
	}

	if (connection_based) {
		if (ip_address.empty() || port == -1) {
			std::cerr << "Error: IP address and port must be specified in connected mode" << std::endl;
			return -1;
		}

		int rc = stockholm.init(ip_address, port);
		if (rc < 0) {
			std::cerr << "Error: Failed to initialize stockholm" << std::endl;
			return -1;
		}
		rc = stockholm.runc();
		if (rc < 0) {
			std::cerr << "Error: Failed to run stockholm" << std::endl;
			return -1;
		}
		return 0;
	} 

	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h"))
			stockholm.setHelp(true);
		else if (!strcmp(argv[i],"--version") || !strcmp(argv[i],"-v"))
			stockholm.setVersion(true);
		else if (!strcmp(argv[i],"--silent") || !strcmp(argv[i],"-s"))
			stockholm.setSilent(true);
		else if (!strcmp(argv[i],"--reverse") || !strcmp(argv[i],"-r"))
		{
			if (i + 1 < argc && argv[i + 1][0] != 0)
			{
				stockholm.setReverse(true);
				stockholm.setKey(argv[i + 1]);
			}
			else
			{
				stockholm.setHelp(true);
			}
		}
	}
	stockholm.run();
}