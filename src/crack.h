#ifndef CRACK_H
#define CRACK_H

#include <stdio.h>
#include <thread>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <iostream>
#include "serverData.h"

int crack(const char* server_ip, int port, int ind, char ch);
int find_comLEN(const char* server_ip, int port);
int computeMSG(char* msg, char* key, int ind = 1);
int computeHMAC(char* hmac_hex, char* key, int ind = 1);
int compute_msg_and_key(char* msg, int ind, char ch);
int generate_key(int ind, char ch, char* key);
void add_correct();
int get_correct();

// All characters used to crack the passkey
inline char ASCII_chars[] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                             'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                             '0','1','2','3','4','5','6','7','8','9','!','"','#','$','%','&','\'','(',')','*','+',',','-','.','/',
                             ':',';','<','=','>','?','{','}','|','~','[',']','^','_','@','`'};

#endif
