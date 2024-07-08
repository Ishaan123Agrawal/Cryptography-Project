#include "header.h"

using namespace std;
//g++ client.cpp -lpthread -lssl -lcrypto -o c

RSA *publicKey, *privateKey;

void printEncryptedMessage(unsigned char encryptedText[], int encryptedLength)
{
	for (int i = 0; i < encryptedLength; ++i)
		printf("%02X", encryptedText[i]);
	cout << endl;
}

int ENCRYPT(char message[], unsigned char encryptedText[], char receiverIP[])
{
	// Data to be encrypted
	const char *plaintext = message;
	int plaintextLength = strlen(plaintext);
	
	//Get Public key of receiver
	string Puk = "./CA/public_key_" + (string)receiverIP + ".pem";
	const char *publicKeyFile = Puk.c_str();
	RSA *publicKey = getPublicKeyFromFile(publicKeyFile);
	
	// Encrypt data using public key
	int encryptedLength = RSAEncrypt(reinterpret_cast<const unsigned char *>(plaintext), plaintextLength, publicKey, encryptedText);
	
	RSA_free(publicKey);
	return encryptedLength;
}

void DECRYPT(char encryptedText[], unsigned char *decryptedText, int encryptedLength)
{
	//Data to be decrypted
	const unsigned char *ciphertext = reinterpret_cast<const unsigned char*>(encryptedText);
	
	//Decrypt data using private key
	int decryptedLength = RSADecrypt(ciphertext, encryptedLength, privateKey, decryptedText);
	decryptedText[decryptedLength] = '\0';
}

void *receive_thread(void *args)
{
	int *sfd_ptr = (int*)args;
    int sfd = *sfd_ptr;
    	
	while(1)
	{
		char *recmsg;
		recmsg = (char*)calloc(BSIZE, sizeof(char));
		
		int bytesReceived = recv(sfd, recmsg, BSIZE, 0);
		if (bytesReceived <= 0) {
			printf("No bytes received\n");
			break;
		}
		recmsg[bytesReceived] = '\0'; 
		cout<<"Message received\n";
		
		char sender[10], receiver[10], encryptedText[MSG_SIZE];
		int encryptedLength;
		parseInput(sender, receiver, encryptedText, recmsg, encryptedLength);
		
		printf("Received Encrypted text: ");
		printEncryptedMessage(reinterpret_cast<unsigned char*>(encryptedText), encryptedLength);
		
		//DECRYPTION FOR FINAL MESSAGE
		fflush(stdout);
		printf("Decrypting message...\n");
		unsigned char *decryptedText;
		decryptedText = (unsigned char *)malloc(BSIZE * sizeof(unsigned char));
		
		DECRYPT(encryptedText, decryptedText, encryptedLength);
		
		printf("Received Message from %s : %s\n\n", sender, reinterpret_cast<char*>(decryptedText));
		free(decryptedText);
	}
	
	pthread_exit(NULL);
}

int main(int argc, char *args[])
{
	if(argc !=2)
	{
		perror("Usage: ./c <IP ADDRESS>");
		exit(1);
	}	
	
	char clientIP[10];
	strcpy(clientIP, args[1]);
	
	/*************** Key Generation ****************************/
	string Puk = "./CA/public_key_" + (string)clientIP + ".pem";
	string Prk = "private_key_" + (string)clientIP + ".pem";
	
	const char *publicKeyFile = Puk.c_str();
	const char *privateKeyFile = Prk.c_str();
	int keyLength = 512; // Key length in bits
	
	printf("Public file: %s\n", publicKeyFile);
	printf("Private file: %s\n", privateKeyFile);

	generateAndSaveRSAKeyPair(publicKeyFile, privateKeyFile, keyLength);
	publicKey = getPublicKeyFromFile(publicKeyFile);
	privateKey = getPrivateKeyFromFile(privateKeyFile);

	cout << "RSA key pair generated and saved successfully." << endl;
	
	/*************** Socket Connection *************************/
	
	int PORT = 7000;
	char serverIP[] = "127.0.0.1";
	char rbuff[BSIZE], sbuff[BSIZE];

	int sfd = socket(AF_INET, SOCK_STREAM, 0);
	
	if(sfd < 0){
		printf("Socket Error\n");
		exit(1);
	}
	
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = PORT;
	serverAddr.sin_addr.s_addr = inet_addr(serverIP);
	
	int status = connect(sfd, (struct sockaddr*) &serverAddr, sizeof(serverAddr));
	
	if(status < 0)
	{
		printf("Connection Error\n");
		exit(1);
	}
	
	printf("My IP: %s\n", clientIP);
	
	printf("Connected to Server!\n");

	send(sfd, clientIP, sizeof(clientIP), 0);
	printf("IP Address sent to server.\n\n");
	
	//Polling for concurrent receive and send
	struct pollfd pfds[1];
	pfds[0].fd = 0;
	pfds[0].events = POLLIN;
	
	//Starting receiver thread
	pthread_t tid;
	pthread_create(&tid, NULL, receive_thread, &sfd);

	while(1)
	{
		char message[MSG_SIZE];
		int ret = poll(pfds, 1, 10);
		if (ret > 0)
		{
			if(pfds[0].revents & POLLIN)
			{
				//Typed message
				fgets(message, MSG_SIZE, stdin);
				message[strcspn(message, "\n")] = '\0';
				
				char receiverIP[10];
				printf("Enter receiver IP: ");
				fgets(receiverIP, 10, stdin);
				receiverIP[strcspn(receiverIP, "\n")] = '\0';
				
				//ENCRYPTION FOR FINAL MESSAGE
				printf("Encrypting message...\n");
				unsigned char encryptedText[MSG_SIZE];
				int encryptedLength = ENCRYPT(message, encryptedText, receiverIP);
				encryptedText[encryptedLength] = '\0';
				
				printf("Encrypted text: ");
				printEncryptedMessage(encryptedText, encryptedLength);
				
				char finalMessage[BSIZE];
				sprintf(finalMessage, "%s|%s|%d|%s", clientIP, receiverIP, encryptedLength, reinterpret_cast<char*>(encryptedText));
				finalMessage[strlen(finalMessage)] = '\0';
				fflush(stdout);
				
				send(sfd, finalMessage, BSIZE, 0);
				printf("Message sent successfully!\n\n");
			}
		}
	}
	
	return 0;
}
