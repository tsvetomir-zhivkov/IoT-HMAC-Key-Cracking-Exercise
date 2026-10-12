#include "main.h"

int main(void){

    // Start the program
    printf("START................\n");

    // Find the command length needed to crack the keyphrase
    find_comLEN(server_ip, server_port);

    // Crack the passphrase

    int correct = 0; // Found characters

    for(int i = 19; i >= 0; i--) {
        for (int ch = 0; ch < sizeof(ASCII_chars); ch++) {
            // Crack the character
            int res = crack(server_ip, server_port, i, ASCII_chars[ch]);
            
            if (res){
                fprintf(stderr,"ERROR #1");
                exit(0);
            }

            // Increment whether a new character is found
            if (get_correct() > correct){
                correct+=1;
                break;
            }
        }
    }

    printf("\nFINISH\n");
}
