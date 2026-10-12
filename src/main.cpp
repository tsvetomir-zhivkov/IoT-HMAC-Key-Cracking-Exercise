#include "main.h"

int main(void){


    printf("START................\n");
    //find_comLEN(server_ip, port);
    //crack(server_ip, port);

char passkey[21] = "--------------------";


char ASCII_chars[] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                             'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                             '0','1','2','3','4','5','6','7','8','9','!','"','#','$','%','&','\'','(',')','*','+',',','-','.','/',
                             ':',';','<','=','>','?','{','}','|','~','[',']','^','_','@','`'};

    int correct = 0;
    for(int i = 19; i >= 0; i--) {
        for (int ch = 0; ch<sizeof(ASCII_chars); ch++) {
            int res = crack(server_ip, port, i, ASCII_chars[ch]);
            if (res){
                exit(0);
            }

            if (get_correct() > correct){
                correct+=1;
                printf("FOUND ONE\n");
                break;
            }
        }
    }

}
