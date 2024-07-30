#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

// Constants
#define TOKEN_SIZE 128
#define PAYLOAD_SIZE (crypto_secretbox_MACBYTES + TOKEN_SIZE)
#define MSG_ASK "Can I get the solution to the challenge, please?"
#define STATUS_BAD 0
#define STATUS_GOOD 1

// Structure for the message
struct message {
  int hacker_id;
  int status;
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char payload[PAYLOAD_SIZE];
};

// Function to handle errors and exit.
void error_handling(const char *message, int exit_code) {
  perror(message);
  exit(exit_code);
}

// Function to read the key from a file.
void read_key(unsigned char *key) {
  // open the key file with binary read mode.
  FILE *file = fopen("/home/hackers/hacker01/key", "rb");
  // Check if openning failed.
  if (file ==NULL) {
    error_handling("Failed to open key file", 1);
  }

  // Try reading the key from the file
  if (fread(key, 1, crypto_secretbox_KEYBYTES, file) != crypto_secretbox_KEYBYTES) {
    // close if can not read/
    fclose(file);
    error_handling("Failed to read the key", 1);
  }
  // Close after reading.
  fclose(file);
}

// Function to print the base64-encoded hash of the decrypted token
void print_token(unsigned char *token, size_t size) {
  // Buffer to store the hash of the token.
  unsigned char hash[crypto_generichash_BYTES];
  //Buffer to store the base 64-encoded hash
  char base64_out[(crypto_generichash_BYTES * 4 /3) + 4];

  // Generate a cryptographic hash using libsodium's generic hash function
  crypto_generichash(hash, sizeof(hash), token, size, NULL, 0);
  // Encode the hash into a base64 string
  sodium_bin2base64(base64_out, sizeof(base64_out), hash, sizeof(hash), sodium_base64_VARIANT_ORIGINAL);
  // Print the solution token in base64
  printf("Solution Token: %s\n", base64_out);
}

int main() {
  // Store server address info
  struct sockaddr_in server_addr;
  // socket descriptor and retry counter.
  int sock, retries = 0;
  // Structure to hold the message and the response
  struct message msg, response;
  // Buffer for the key
  unsigned char server_key[crypto_secretbox_KEYBYTES];

  // Init Sodium Library
  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to init Sodium.\n");
    return 1;
  }

  // Load the key
  read_key(server_key);

  // Create socket
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    error_handling("Socket creation failed", 1);
  }

  // Server Address Details.
  memset(&server_addr, 0, sizeof(server_addr));
  // Internet address family.
  server_addr.sin_family = AF_INET;
  // Server port converted to network byte order.
  server_addr.sin_port = htons(4000);
  // Ip adddress
  server_addr.sin_addr.s_addr = inet_addr("192.168.1.77");

  // Connect to the server
  if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    // Handle connection error
    perror("Connection failed");
    // Close socket
    close(sock);
    // Exit
    return 1;
  }

  // Retry Loop
  while (retries < 250) {
    // clear the msg structure
    memset(&msg, 0, sizeof(msg));
    // Set the message into payload.
    memcpy(msg.payload, MSG_ASK, strlen(MSG_ASK));
    // Generate a nonce for encryption
    randombytes_buf(msg.nonce, sizeof(msg.nonce));
    msg.hacker_id = 01;

    // Encrypt the message with libsodiums authenticated encryption.
    if (crypto_secretbox_easy(msg.payload, msg.payload, TOKEN_SIZE, msg.nonce, server_key) !=0) {
      // Print the error
      fprintf(stderr, "Encryption failed\n");
      // Retry
      continue;
    }

    // Send the encrypted message
    if (send(sock, &msg, sizeof(msg), 0) != sizeof(msg)) {
      // Print error.
      perror("Failed to send the message");
      // retry
      continue;
    }

    //Receive the response
    if (recv(sock, &response, sizeof(response), 0) != sizeof(response)) {
      // Print error.
      perror("Failed to receive message");
      // retry
      continue;
    }

    //Check the status of received msg.
    if (response.status == STATUS_BAD) {
      // print error
      printf("Error from server: %s\n", response.payload);
      // retry
      continue;
    }

    // Decrypt the received message
    unsigned char decrypted[TOKEN_SIZE];
    if (crypto_secretbox_open_easy(decrypted,response.payload, PAYLOAD_SIZE, response.nonce, server_key) != 0) {
      // print error if decryption fails
      fprintf(stderr, "Decryption failed\n");
      // retry
      continue;
    }

    //Print the solution token in Base64
    print_token(decrypted, sizeof(decrypted));
    // break the loop
    break;
  }

  // Cleanup and close the socket
  close(sock);
  return 0; //success
}
