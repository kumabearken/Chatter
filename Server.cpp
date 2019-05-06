#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <vector>
#include <fstream>

#pragma comment (lib, "Ws2_32.lib")

#define IP_ADDRESS "192.168.1.68"
#define DEFAULT_PORT "8000"
#define DEFAULT_BUFLEN 512

struct client_type
{
	int id;
	std::string login;
	SOCKET socket;
	std::string status;
	std::string publicKey;
	std::string serverPrivKey;
};

const char OPTION_VALUE = 1;
const int MAX_CLIENTS = 5;

//Function Prototypes
int process_client(client_type& new_client, std::vector<client_type>& client_array, std::thread& thread);
int main();

//rsa stuff=================================================================
std::string ce(long int t, long int* e, long int   p, long int   q, long int* d);
long int cd(long int, long int);
std::string encrypt(long int, long int, std::string);
std::string decrypt(long int, long int, std::string);
std::string getKeys();
long int tt[100];
//===========================================================================

int process_client(client_type& new_client, std::vector<client_type>& client_array, std::thread& thread)
{
	std::string msg = "";
	char tempmsg[DEFAULT_BUFLEN] = "";

	//Session
	while (1)
	{
		memset(tempmsg, 0, DEFAULT_BUFLEN);
		msg = "";
		if (new_client.socket != 0)
		{
			int iResult = recv(new_client.socket, tempmsg, DEFAULT_BUFLEN, 0);
			msg = "";
			if (iResult != SOCKET_ERROR)
			{
				//std::cout
				msg = "";
				//if //online typed in chat can see who is online
				if (std::string(tempmsg) == "//online")
				{
					for (int i = 0; i < MAX_CLIENTS; i++)
					{
						if (client_array[i].socket != INVALID_SOCKET)
							if (new_client.id != i)
								msg += client_array[i].login + " is online\n";
					}
					if (msg == "")
					{
						msg += "no one else is online\n";
					}
					iResult = send(new_client.socket, msg.c_str(), strlen(msg.c_str()), 0);
				}
				
				// quit
				else if (std::string(tempmsg) == "//quit")
				{
					msg = "Client " + new_client.login + " Disconnected";

					std::cout << msg << std::endl;

					closesocket(new_client.socket);
					closesocket(client_array[new_client.id].socket);
					client_array[new_client.id].socket = INVALID_SOCKET;

					//Broadcast the disconnection message to the other clients
					for (int i = 0; i < MAX_CLIENTS; i++)
					{
						if (client_array[i].socket != INVALID_SOCKET)
							iResult = send(client_array[i].socket, msg.c_str(), strlen(msg.c_str()), 0);
					}

					break;
				}

				// general chat
				else if (iResult != SOCKET_ERROR)
				{
					if (strcmp("", tempmsg))
						msg = "Client " + new_client.login + ": " + tempmsg;

					std::cout << msg.c_str() << std::endl;
					std::string s = new_client.serverPrivKey;
					std::string delimiter = " ";
					std::string privKey = s.substr(0, s.find(delimiter));
					s.erase(0, s.find(delimiter) + delimiter.length());
					std::string n = s;
					msg = decrypt(stoi(n), stoi(privKey), (std::string)tempmsg);
					//Broadcast that message to the other clients
					for (int i = 0; i < MAX_CLIENTS; i++)
					{
						if (client_array[i].socket != INVALID_SOCKET)
							if (new_client.id != i)
								iResult = send(client_array[i].socket, msg.c_str(), strlen(msg.c_str()), 0);
					}
				}
				//	default quit if fails	
				else
				{
					msg = "Client " + new_client.login + " Disconnected";

					std::cout << msg << std::endl;

					closesocket(new_client.socket);
					closesocket(client_array[new_client.id].socket);
					client_array[new_client.id].socket = INVALID_SOCKET;

					//Broadcast the disconnection message to the other clients
					for (int i = 0; i < MAX_CLIENTS; i++)
					{
						if (client_array[i].socket != INVALID_SOCKET)
							iResult = send(client_array[i].socket, msg.c_str(), strlen(msg.c_str()), 0);
					}

					break;
				}
			}
			else
			{
				msg = "Client " + new_client.login + " Disconnected";

				std::cout << msg << std::endl;

				closesocket(new_client.socket);
				closesocket(client_array[new_client.id].socket);
				client_array[new_client.id].socket = INVALID_SOCKET;

				//Broadcast the disconnection message to the other clients
				for (int i = 0; i < MAX_CLIENTS; i++)
				{
					if (client_array[i].socket != INVALID_SOCKET)
						iResult = send(client_array[i].socket, msg.c_str(), strlen(msg.c_str()), 0);
				}

				break;
			}
		}
	} //end while

	thread.detach();

	return 0;
}

int main()
{
	WSADATA wsaData;
	struct addrinfo hints;
	struct addrinfo* server = NULL;
	SOCKET server_socket = INVALID_SOCKET;
	std::string msg = "";
	std::vector<client_type> client(MAX_CLIENTS);
	int num_clients = 0;
	int temp_id = -1;
	std::thread my_thread[MAX_CLIENTS];

	//Initialize Winsock
	std::cout << "Intializing Winsock..." << std::endl;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	//Setup hints
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	//Setup Server
	std::cout << "Setting up server..." << std::endl;
	getaddrinfo(static_cast<LPCTSTR>(IP_ADDRESS), DEFAULT_PORT, &hints, &server);

	//Create a listening socket for connecting to server
	std::cout << "Creating server socket..." << std::endl;
	server_socket = socket(server->ai_family, server->ai_socktype, server->ai_protocol);

	//Setup socket options
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &OPTION_VALUE, sizeof(int)); //Make it possible to re-bind to a port that was used within the last 2 minutes
	setsockopt(server_socket, IPPROTO_TCP, TCP_NODELAY, &OPTION_VALUE, sizeof(int)); //Used for interactive programs

	//Assign an address to the server socket.
	std::cout << "Binding socket..." << std::endl;
	bind(server_socket, server->ai_addr, (int)server->ai_addrlen);

	//Listen for incoming connections.
	std::cout << "Listening..." << std::endl;
	listen(server_socket, SOMAXCONN);
	
	// create keys
	std::string n = getKeys();
	std::cout << n << '\n';
	std::string delimiter = " ";
	std::string publicKey = n.substr(0, n.find(delimiter));
	n.erase(0, n.find(delimiter) + delimiter.length());
	std::string privKey = n.substr(0, n.find(delimiter));
	n.erase(0, n.find(delimiter) + delimiter.length());
	publicKey += " " + n;
	privKey += " " + n;
	std::cout << publicKey << " " << privKey << '\n';
	
	//Initialize the client list
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		client[i] = { -1, "" ,INVALID_SOCKET };
	}

	while (1)
	{

		SOCKET incoming = INVALID_SOCKET;
		incoming = accept(server_socket, NULL, NULL);

		if (incoming == INVALID_SOCKET) continue;

		//Reset the number of clients
		num_clients = -1;

		//Create a temporary id for the next client
		temp_id = -1;
		for (int i = 0; i < MAX_CLIENTS; i++)
		{
			if (client[i].socket == INVALID_SOCKET && temp_id == -1)
			{
				client[i].socket = incoming;
				client[i].id = i;
				temp_id = i;
			}

			if (client[i].socket != INVALID_SOCKET)
				num_clients++;

			//std::cout << client[i].socket << std::endl;
		}

		//check login and password===================================
		char temp[DEFAULT_BUFLEN] = "";
		std::string login;
		std::string pw;
		bool valid = false;// check if valid user
		if (temp_id != -1)
		{
			// get login info
			recv(client[temp_id].socket, temp, DEFAULT_BUFLEN, 0);

			// parsing
			std::string s;
			std::string delimiter = " ";
			s = std::string(temp);
			login = s.substr(0, s.find(delimiter));
			s.erase(0, s.find(delimiter) + delimiter.length());
			pw = s;

			//check login txt file
			std::ifstream inFile;
			inFile.open("LoginInfo.txt");
			if (!inFile) {
				std::cerr << "Unable to open file datafile.txt";
				exit(1);   // call system to stop
			}

			// check if password and login match
			while (inFile)
			{
				getline(inFile, s);
				std::string x = s.substr(0, s.find(delimiter));
				if (login == x)
				{
					s.erase(0, s.find(delimiter) + delimiter.length());
					if (pw == s)
						valid = true;
				}
			}
		}
		//============================================================
	
		if ((temp_id != -1) && valid)
		{
			//Send the id to that client
			client[temp_id].login = login;//set chat name
			client[temp_id].status = "ONLINE";//set online status
			std::cout << "Client " << client[temp_id].login << " Accepted" << std::endl;
			msg = std::to_string(client[temp_id].id);
			send(client[temp_id].socket, msg.c_str(), strlen(msg.c_str()), 0);

			//receive publickey
			//=== send and receive keys
			memset(temp, 0, DEFAULT_BUFLEN);
			recv(client[temp_id].socket, temp, DEFAULT_BUFLEN, 0);
			std::string clientKey = std::string(temp);
			send(client[temp_id].socket, publicKey.c_str(), strlen(publicKey.c_str()), 0);
			client[temp_id].publicKey = clientKey;
			client[temp_id].serverPrivKey = privKey;
			std::cout << std::string(clientKey) <<'\n';
			//Create a thread process for that client
			my_thread[temp_id] = std::thread(process_client, std::ref(client[temp_id]), std::ref(client), std::ref(my_thread[temp_id]));
		}
		else//not valid
		{
			if (!valid)
				msg = "Invalid Login or Password";
			else
				msg = "Server is full";
			send(incoming, msg.c_str(), strlen(msg.c_str()), 0);
			std::cout << msg << std::endl;
		}
	} //end while


	//Close listening socket
	closesocket(server_socket);

	//Close client socket
	for (int i = 0; i < MAX_CLIENTS; i++)
	{
		my_thread[i].detach();
		closesocket(client[i].socket);
	}

	//Clean up Winsock
	WSACleanup();
	std::cout << "Program has ended successfully" << std::endl;

	system("pause");
	return 0;
}
//====RSA stuff=====================================================
// check if prime
long int  prime(long int  pr)
{
	long int  i;
	long int  j = sqrt(pr);
	for (i = 2; i <= j; i++)
	{
		if (pr % i == 0)
			return 0;
	}
	return 1;
}

// find a prime number
long int  findPrime()
{
	//start seed
	srand(time(NULL));
	bool fPrime = true;
	long int temp;
	while (fPrime)
	{
		temp = rand() % 100 + 1;
		if (prime(temp))
			return temp;
	}
}

std::string getKeys()
{
	// find 2 random prime numbers
	long int p;
	long int q;
	p = findPrime();
	q = findPrime();
	while (p == 0)
	{
		p = findPrime();
	}
	while (p == q || q == 0)
	{
		q = findPrime();
	}
	long int n;
	long int t;
	long int e[100];//encKey at 0
	long int d[100];//decKey at 0
	n = p * q;
	t = (p - 1) * (q - 1);
	std::string key = ce(t, e, p, q, d);
	key += " " + std::to_string(n);
	return key;
}
std::string ce(long int t, long int* e, long int p, long int q, long int* d)
{
	int k;
	k = 0;
	long int i;
	long int flag;
	for (i = 2; i < t; i++)
	{
		if (t % i == 0)
			continue;
		flag = prime(i);
		if (flag == 1 && i != p && i != q)
		{
			e[k] = i;
			flag = cd(e[k], t);
			if (flag > 0)
			{
				d[k] = flag;
				k++;
			}
			if (k == 99)
				break;
		}
	}
	std::string s = std::to_string(e[1]);
	s += " ";
	s += std::to_string(d[1]);
	return s;
}

long int cd(long int x, long int t)
{
	long int k = 1;
	while (1)
	{
		k = k + t;
		if (k % x == 0)
			return (k / x);
	}
}

// encrypt message need private key, the n , and the encrypted message
std::string encrypt(long int eKey, long int n, std::string message)
{
	long int pt, ct, j, k, len;
	long int i = 0;
	//long int temp[100];
	const char* mess = message.c_str();
	long int encrypted[100];
	len = message.length();
	while (i != len)
	{
		pt = mess[i];
		pt = pt - 96;
		k = 1;
		for (j = 0; j < eKey; j++)
		{
			k = k * pt;
			k = k % n;
		}
		tt[i] = k;
		ct = k + 96;
		encrypted[i] = ct;
		i++;
	}
	encrypted[i] = -1;
	char arr[100] = "";
	std::cout << "\nTHE ENCRYPTED MESSAGE IS\n";
	for (i = 0; encrypted[i] != -1; i++)
		printf("%c", encrypted[i]);
	for (i = 0; encrypted[i] != -1; i++)
		arr[i] = encrypted[i] + '0';
	std::string s = std::string(arr);
	arr[i] = NULL;
	return s;
}

// decrypt message need private key, the n , and the encrypted message
std::string decrypt(long int dKey, long int n, std::string encrypted)
{
	long int pt, ct, j, k, len;
	long int i = 0;
	long int decrypted[100];
	long int mess[100];
	for (i = 0; i < encrypted.length(); ++i)
	{
		mess[i] = encrypted[i];
	}
	mess[i] = -1;
	//long int tt[100];
	i = 0;
	while (mess[i] != -1)
	{
		ct = tt[i];
		k = 1;
		for (j = 0; j < dKey; j++)
		{
			k = k * ct;
			k = k % n;
		}
		pt = k + 96;
		decrypted[i] = pt;
		i++;
	}
	decrypted[i] = -1;
	char arr[100];
	std::cout << "\nTHE DECRYPTED MESSAGE IS\n";
	for (i = 0; decrypted[i] != -1; i++)
		printf("%c", decrypted[i]);
	for (i = 0; decrypted[i] != -1; i++)
		arr[i] = decrypted[i] + '0';
	arr[i] = NULL;
	std::string s = std::string(arr);
	return s;
}
