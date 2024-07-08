#include <bits/stdc++.h>
#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <sys/poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>

#define BSIZE 2048
#define MSG_SIZE 1024

using namespace std;

void parseInput(char sender[], char receiver[], char actualMessage[], char message[], int &encryptedLength)
{
	char* token = strtok(message, "|");
	strcpy(sender, token);
	sender[strlen(sender)] = '\0';
	
	token = strtok(NULL, "|");
	strcpy(receiver, token);
	receiver[strlen(receiver)] = '\0';
	
	char length[10];
	token = strtok(NULL, "|");
	strcpy(length, token);
	length[strlen(length)] = '\0';
	encryptedLength = stoi(length);
	
	token = strtok(NULL, "|");
	strcpy(actualMessage, token);
	actualMessage[strlen(actualMessage)] = '\0';
}

// Function to handle errors
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to encrypt data using RSA public key
int RSAEncrypt(const unsigned char *plaintext, int plaintext_len, RSA *pubKey, unsigned char *encryptedText) {
	int padding = RSA_PKCS1_PADDING;
    int encryptedLength = RSA_public_encrypt(plaintext_len, plaintext, encryptedText, pubKey, padding);
    if (encryptedLength == -1) {
        handleErrors();
    }
    return encryptedLength;
}

// Function to decrypt data using RSA private key
int RSADecrypt(const unsigned char *encryptedText, int encryptedLength, RSA *privKey, unsigned char *decryptedText) {
	int padding = RSA_PKCS1_PADDING;
    int decryptedLength = RSA_private_decrypt(encryptedLength, encryptedText, decryptedText, privKey, padding);
    if (decryptedLength == -1) {
        handleErrors();
    }
    return decryptedLength;
}

RSA* getPublicKeyFromFile(const char *publicKeyFile)
{
	// Load public key from file
	FILE *publicKeyFilePtr = fopen(publicKeyFile, "rb");
	if (!publicKeyFilePtr) {
		cerr << "Error: Failed to open public key file" << endl;
		handleErrors();
	}
	RSA *publicKey = PEM_read_RSAPublicKey(publicKeyFilePtr, nullptr, nullptr, nullptr);
	if (!publicKey) {
		cerr << "Error: Failed to read public key from file" << endl;
		handleErrors();
	}
	fclose(publicKeyFilePtr);
	
	return publicKey;
}

RSA* getPrivateKeyFromFile(const char *privateKeyFile)
{
	// Load private key from file
    FILE *privateKeyFilePtr = fopen(privateKeyFile, "rb");
    if (!privateKeyFilePtr) {
        cerr << "Error: Failed to open private key file" << endl;
        handleErrors();
    }
    RSA *privateKey = PEM_read_RSAPrivateKey(privateKeyFilePtr, nullptr, nullptr, nullptr);
    if (!privateKey) {
        cerr << "Error: Failed to read private key from file" << endl;
        handleErrors();
    }
    fclose(privateKeyFilePtr);
    
    return privateKey;
}

// Function to generate RSA key pair and save to files
void generateAndSaveRSAKeyPair(const char *publicKeyFile, const char *privateKeyFile, int keyLength) {
    RSA *rsa = nullptr;
    BIGNUM *bignum = nullptr;

    // Generate RSA key pair
    rsa = RSA_new();
    bignum = BN_new();
    int ret = BN_set_word(bignum, RSA_F4);
    if (ret != 1) {
        cerr << "Failed to set RSA exponent" << endl;
        handleErrors();
    }

    ret = RSA_generate_key_ex(rsa, keyLength, bignum, nullptr);
    if (ret != 1) {
        cerr << "Failed to generate RSA key pair" << endl;
        handleErrors();
    }

    // Save public key to file
    FILE *publicKeyFilePtr = fopen(publicKeyFile, "wb");
    if (!publicKeyFilePtr) {
        cerr << "Error: Failed to open public key file" << endl;
        handleErrors();
    }

    ret = PEM_write_RSAPublicKey(publicKeyFilePtr, rsa);
    if (ret != 1) {
        cerr << "Error: Failed to write public key to file" << endl;
        handleErrors();
    }

    fclose(publicKeyFilePtr);

    // Save private key to file
    FILE *privateKeyFilePtr = fopen(privateKeyFile, "wb");
    if (!privateKeyFilePtr) {
        cerr << "Error: Failed to open private key file" << endl;
        handleErrors();
    }

    ret = PEM_write_RSAPrivateKey(privateKeyFilePtr, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    if (ret != 1) {
        cerr << "Error: Failed to write private key to file" << endl;
        handleErrors();
    }

    fclose(privateKeyFilePtr);

    // Cleanup
    RSA_free(rsa);
    BN_free(bignum);
}
