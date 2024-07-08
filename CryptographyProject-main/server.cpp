#include "header.h"

using namespace std;
//g++ server.cpp -lpthread -lssl -lcrypto -o s

#define MAX_CLIENTS 100

// Global array of semaphores, one for each client
sem_t semaphores[MAX_CLIENTS + 4];

RSA *publicKey, *privateKey;

//Maps
map<int, string> nsfdToIp;
map<string, int> ipToNsfd;
int sfd;

// Node structure
struct Node {
    string data;
    Node* next;
};

// Linked list structure
struct LinkedList {
    Node* head;
    Node* tail;
};

// Initialize the linked list
void initLinkedList(LinkedList& list) {
    list.head = nullptr;
    list.tail = nullptr;
}

// Map to store messages for each receiver
map<string, LinkedList> Outbox;

// Insertion at the end
void insertAtEnd(LinkedList& list, string& data) {
    Node* newNode = new Node{data, nullptr};
    if (!list.head) {
        list.head = newNode;
        list.tail = newNode;
    } else {
        list.tail->next = newNode;
        list.tail = newNode;
    }
}

string deleteFromFront(LinkedList& list) 
{
    if (list.head == nullptr) 
        return "";

    Node* temp = list.head;
    list.head = list.head->next;

    if (list.head == nullptr)
        list.tail = nullptr;

    string deletedData = temp->data;
    delete temp;
    return deletedData;
}

// Print the linked list
void print(const LinkedList& list) {
    Node* temp = list.head;
    while (temp != nullptr) {
        cout << temp->data << " ";
        temp = temp->next;
    }
    cout << endl;
}

void stringToCharArray(string& str, char charArray[], size_t maxSize)
{
    strncpy(charArray, str.c_str(), maxSize - 1);
    charArray[maxSize - 1] = '\0';
}

void* client_thread_inbox(void *args)
{
	int *nsfd_ptr = (int*)args;
    int nsfd = *nsfd_ptr;
    	
    char ipbuff[10];
		
	//Keeping track of mapping between Client's nsfd and IP address
	recv(nsfd, ipbuff, sizeof(ipbuff), 0);
	printf("IP received: %s\n\n", ipbuff);
	
	string ip(ipbuff);
	
	nsfdToIp[nsfd] = ip;
	ipToNsfd[ip] = nsfd;
	
	//INITIALIZE OUTBOX FOR THIS CLIENT
	LinkedList newList;
	initLinkedList(newList);
	Outbox[ip] = newList;
	
	while(1)
	{
		char *rebuff;
		rebuff = (char*)calloc(BSIZE, sizeof(char));
		
		int bytesReceived = recv(nsfd, rebuff, BSIZE, 0);
		if (bytesReceived <= 0) {
			printf("No bytes received\n");
			break;
		}
		rebuff[bytesReceived] = '\0'; 
		printf("Message received: %s\n", rebuff);
		
		char copy_rebuff[BSIZE];
		strcpy(copy_rebuff, rebuff);
		
		char sender[10], receiver[10], message[MSG_SIZE];
		int encryptedLength;
		parseInput(sender, receiver, message, rebuff, encryptedLength);
		
		string receiver_ip(receiver);
		sem_wait(&semaphores[nsfd]);

		string strMessage(copy_rebuff);
		insertAtEnd(Outbox[receiver_ip], strMessage);
		
		printf("Message inserted into Inbox of %s.\n", receiver);
		sem_post(&semaphores[nsfd]);
	}
	
	pthread_exit(NULL);
}

void* client_thread_outbox(void *args)
{
	int *nsfd_ptr = (int*)args;
    int nsfd = *nsfd_ptr;
    
    sleep(2);
    
    string ip = nsfdToIp[nsfd];
    
    while(1)
	{
		sem_wait(&semaphores[nsfd]);

		string message = deleteFromFront(Outbox[ip]);
		if(message != "")
		{
			cout<<"\nMessage deleted from Outbox of "<<ip<<endl;
			
			const char* charArray = message.c_str();
			size_t length = strlen(charArray);
			char msg[length + 1];
			strcpy(msg, charArray);
			
			send(nsfd, msg, BSIZE, 0);
			cout<<"Message sent to "<<ip<<"\n\n";
		}

		sem_post(&semaphores[nsfd]);
		sleep(1);
    }
	
	pthread_exit(NULL);
}

int main()
{
	//system("rm -r CA");
    //system("mkdir CA");
    /*************** Key Generation ****************************/
    const char *publicKeyFile = "./CA/public_key_server.pem";
    const char *privateKeyFile = "private_key_server.pem";
    int keyLength = 512; // Key length in bits

    generateAndSaveRSAKeyPair(publicKeyFile, privateKeyFile, keyLength);

    cout << "RSA key pair generated and saved successfully." << endl;
    publicKey = getPublicKeyFromFile(publicKeyFile);
    privateKey = getPrivateKeyFromFile(privateKeyFile);

    /*************** Socket Connection *************************/
    int PORT = 7000;
    socklen_t addrSize;
    char serverIP[] = "127.0.0.1";

    int sfd = socket(AF_INET, SOCK_STREAM, 0);

    if(sfd < 0){
        printf("Socket Error\n");
        exit(1);
    }

    int option = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option));

    struct sockaddr_in serverAddr, clientAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = PORT;
    serverAddr.sin_addr.s_addr = inet_addr(serverIP);

    int bf = bind(sfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    if(bf < 0){
        printf("Bind Error\n");
        exit(1);
    }

    listen(sfd, 1);
    printf("Listening...\n\n");

    while(1)
    {
        int *nsfd = (int*)malloc(10 * sizeof(int)); // Dynamically allocate memory for nsfd
        *nsfd = accept(sfd, (struct sockaddr*)&clientAddr, &addrSize);

        sem_init(&semaphores[*nsfd], 0, 1); // Initialize semaphore with value 1

        pthread_t tid1, tid2;
        pthread_create(&tid1, NULL, client_thread_inbox, nsfd);
        pthread_create(&tid2, NULL, client_thread_outbox, nsfd);
    }

    return 0;
}
