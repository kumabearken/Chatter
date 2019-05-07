#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <math.h>
#include <string.h>
#include <time.h>
using namespace std;

//rsa stuff=================================================================
string ce(long int t, long int* e, long int   p, long int   q, long int* d);
long int cd(long int, long int);
string encrypt(long int, long int, string);
string decrypt(long int, long int, string);
string getKeys();
//===========================================================================

bool display = true;

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 1024            
#define IP_ADDRESS "192.168.1.68"
#define DEFAULT_PORT "8000"

class client_type
{
public:
	SOCKET socket;
	int id;
	string login;
	string serverPubKey;
	string myPrivKey;
	char received_message[DEFAULT_BUFLEN];
};

int process_client(client_type& new_client);
int main();

// threaded process to allow realtime messages
int process_client(client_type& new_client)
{
	while (1)
	{
		memset(new_client.received_message, 0, DEFAULT_BUFLEN);

		if (new_client.socket != 0)
		{
			int iResult = recv(new_client.socket, new_client.received_message, DEFAULT_BUFLEN, 0);
						
			if (iResult != SOCKET_ERROR)
			{
				string s = new_client.myPrivKey;
				string delimiter = " ";
				string privKey = s.substr(0, s.find(delimiter));
				s.erase(0, s.find(delimiter) + delimiter.length());
				string n = s;
				if (display)
				{
					cout << "My n is " << n << " my pri Key is " << privKey << " and the message is " << new_client.received_message << '\n';
				}
				s = new_client.received_message;
				s = decrypt(stoi(privKey), stoi(n), s);
				cout << s << endl;
			}
			else
			{
				cout << "recv() failed: " << WSAGetLastError() << endl;
				break;
			}
		}
	}

	if (WSAGetLastError() == WSAECONNRESET)
		cout << "The server has disconnected" << endl;

	return 0;
}

int main()
{
	WSAData wsa_data;
	struct addrinfo* result = NULL, * ptr = NULL, hints;
	string sent_message = "";
	client_type client = { INVALID_SOCKET, -1, "" };
	int iResult = 0;
	string message;

	cout << "Starting Client...\n";

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (iResult != 0) {
		cout << "WSAStartup() failed with error: " << iResult << endl;
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	cout << "Connecting...\n";

	// Resolve the server address and port
	iResult = getaddrinfo(static_cast<LPCTSTR>(IP_ADDRESS), DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		cout << "getaddrinfo() failed with error: " << iResult << endl;
		WSACleanup();
		system("pause");
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		client.socket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (client.socket == INVALID_SOCKET) {
			cout << "socket() failed with error: " << WSAGetLastError() << endl;
			WSACleanup();
			system("pause");
			return 1;
		}

		// Connect to server.
		iResult = connect(client.socket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(client.socket);
			client.socket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);
	// if socket did not connect give message
	if (client.socket == INVALID_SOCKET) {
		cout << "Unable to connect to server!" << endl;
		WSACleanup();
		system("pause");
		return 1;
	}
	cout << "Successfully Connected" << endl;
	// create keys

	string n = getKeys();
	//cout << n << '\n';
	string delimiter = " ";
	string publicKey = n.substr(0, n.find(delimiter));
	n.erase(0, n.find(delimiter) + delimiter.length());
	client.myPrivKey = n.substr(0, n.find(delimiter));
	n.erase(0, n.find(delimiter) + delimiter.length());
	publicKey += " " + n;
	client.myPrivKey += " " + n;
	if (display)
	{
		cout << "My Public is " << publicKey << " My private is " << client.myPrivKey << '\n';
	}
	// send key and receive key
	send(client.socket, publicKey.c_str(), strlen(publicKey.c_str()), 0);
	//=send login and password==========================================
	string login;
	string pw;
	cout << "Insert Login: ";
	getline(cin, login);
	cout << "Insert Pasword: ";
	getline(cin, pw);
	login += " ";
	login += pw;
	send(client.socket,login.c_str(), strlen(login.c_str()), 0);
	
	message = "";
	//Obtain id from server for this client;
	recv(client.socket, client.received_message, DEFAULT_BUFLEN, 0);
	n = "";
	n = string(client.received_message);
	
	bool clear = ((n != "Server is full") && (n != "Invalid Login or Password"));
	
	//receive server key
	recv(client.socket, client.received_message, DEFAULT_BUFLEN, 0);
	message = string(client.received_message);
	client.serverPubKey = message;
	//cout << "server public is " << message << '\n';
	// allow entry if server not full and login was valid
	if (clear)
	{
		client.id = atoi(n.c_str());
		
		//create thread to receive message realtime
		thread my_thread(process_client, ref(client));

		while (1)
		{
			//prevents crashing when user inputs blank message
			sent_message = "";
			getline(cin, sent_message);
			string first_word = sent_message.substr(0, sent_message.find(delimiter));
			if (sent_message == "")
			{
				continue;
			}
			//when wanting to quit
			else if (sent_message == "//quit")
			{
				cout << "Goodbye\n";
				string s = client.serverPubKey;
				string delimiter = " ";
				string serverKey = s.substr(0, s.find(delimiter));
				s.erase(0, s.find(delimiter) + delimiter.length());
				string n = s;
				sent_message = encrypt(stoi(serverKey), stoi(n), sent_message);
				send(client.socket, sent_message.c_str(), strlen(sent_message.c_str()), 0);
				break;
			}
			//if private messaging
			//format = //dm user_name message
			else if (first_word == "//dm")
			{
				string s = client.serverPubKey;
				string serverKey = s.substr(0, s.find(delimiter));
				s.erase(0, s.find(delimiter) + delimiter.length());
				string n = s;
				sent_message = encrypt(stoi(serverKey), stoi(n), sent_message);
				iResult = send(client.socket, sent_message.c_str(), strlen(sent_message.c_str()), 0);
				if (iResult <= 0)
				{
					cout << "send() failed: " << WSAGetLastError() << endl;
					break;
				}
			}
			//continue chat
			else
			{
				string s = client.serverPubKey;
				if (display)
				{
					cout << "Server public key:" << client.serverPubKey << '\n';
				}
				string delimiter = " ";
				string serverKey = s.substr(0, s.find(delimiter));
				s.erase(0, s.find(delimiter) + delimiter.length());
				string n = s;
				if (display)
				{
					cout << "server n is " << n << " server key is " << serverKey << " message is " << sent_message << '\n';
				}
				sent_message = encrypt(stoi(serverKey), stoi(n), sent_message);
				iResult = send(client.socket, sent_message.c_str(), strlen(sent_message.c_str()), 0);
			}
			if (iResult <= 0)
			{
				cout << "send() failed: " << WSAGetLastError() << endl;
				break;
			}
		}

		//Shutdown the connection since no more data will be sent
		my_thread.detach();
	}
	//failed message
	//else
	//	cout << n << endl;

	//close socket
	cout << "Shutting down socket..." << endl;
	iResult = shutdown(client.socket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		cout << "shutdown() failed with error: " << WSAGetLastError() << endl;
		closesocket(client.socket);
		WSACleanup();
		system("pause");
		return 1;
	}

	closesocket(client.socket);
	WSACleanup();
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

string getKeys()
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
	string key = ce(t, e, p, q, d);
	key += " " + to_string(n);
	return key;
}
string ce(long int t, long int* e, long int p, long int q, long int* d)
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
	string s = to_string(e[0]);
	s += " ";
	s += to_string(d[0]);
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
	while (i < len)
	{
		pt = int(mess[i]);
		pt = pt - 96;
		k = 1;
		for (j = 0; j < eKey; j++)
		{
			k = k * pt;
			k = k % n;
		}
		//tt[i] = k;
		ct = k + 96;
		encrypted[i] = ct;
		i++;
	}
	encrypted[i] = -1;
	encrypted[i + 1] = NULL;
	char arr[100] = "";
	if (display)
	{
		std::cout << "\nTHE ENCRYPTED MESSAGE IS\n";
		for (i = 0; encrypted[i] != -1; i++)
			printf("%c", encrypted[i]);
		cout << '\n';
	}
	std::string s;
	for (i = 0; encrypted[i] != -1; i++)
	{
		s += std::to_string(encrypted[i]);
		s += " ";
	}
	s += std::to_string(-1);
	if (display)
	{
		cout << s << '\n';
	}
	return s;
}

// decrypt message need private key, the n , and the encrypted message
std::string decrypt(long int dKey, long int n, std::string encrypted)
{
	long int pt, ct, j, k, len;
	long int i = 0;
	long int decrypted[100];
	long int mess[100];
	while (encrypted != "-1")
	{
		std::string theLI;
		std::string delimiter = " ";
		theLI = encrypted.substr(0, encrypted.find(delimiter));
		encrypted.erase(0, encrypted.find(delimiter) + delimiter.length());
		mess[i] = stol(theLI);
		++i;
	}
	mess[i] = -1;
	i = 0;
	while (mess[i] != -1)
	{
		ct = mess[i] - 96;
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
	if (display)
	{
		std::cout << "\nTHE DECRYPTED MESSAGE IS\n";
		for (i = 0; decrypted[i] != -1; i++)
			printf("%c", decrypted[i]);
		std::cout << '\n';
	}
	for (i = 0; decrypted[i] != -1; i++)
		arr[i] = decrypted[i];
	arr[i] = NULL;
	std::string s = std::string(arr);
	return s;
}
