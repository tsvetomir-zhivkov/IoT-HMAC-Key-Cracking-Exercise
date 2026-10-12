#ifndef CRACK_H
#define CRACK_H

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <iostream>

int crack(const char* server_ip, int port, int ind, char ch);
int find_comLEN(const char* server_ip, int port);
int computeMSG(char* msg, char* key, int ind = 1);
int computeHMAC(char* hmac_hex, char* key, int ind = 1);
int compute_msg_and_key(char* msg, int ind, char ch);
int generate_key(int ind, char ch, char* key);
void add_correct();
int get_correct();

#endif
