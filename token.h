#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define TOKEN_LEN 15

/**
 * generate alpha-numeric string based on random char*
 * 
 * INPUT: fixed length of 16
 * OUTPUT: rotated string
 * */
char* generate_access_token(char* clientIdToken) {
    char *token = (char *) malloc(TOKEN_LEN * sizeof(char*));
    int i, key, used[TOKEN_LEN];
    int rotationIndex = TOKEN_LEN;

    memset(used, 0, TOKEN_LEN * sizeof(int));
    for (i = 0; i < TOKEN_LEN; i++) {
        do {
            key = rand() % rotationIndex;
        } while (used[key] == 1);
        token[i] = clientIdToken[key];
        used[key] = 1;
    }
    token[TOKEN_LEN] = '\0';
    return token;
}


/**
 * generate string by shifting the input to the right once (Caesar cipher)
 *
 * INPUT: fixed length of 16
 * OUTPUT: rotated string
 * */
char* generate_shift_token(char* clientIdToken, int shift) {
    char *token = (char *) malloc(TOKEN_LEN * sizeof(char*));
    int i, key;

    for (i = 0; i < TOKEN_LEN; i++) {
        if (clientIdToken[i] <= '9') {
            token[i] = '0' + (clientIdToken[i] - '0' + shift) % 10;
        } else if (clientIdToken[i] <= 'Z') {
            token[i] = 'A' + (clientIdToken[i] - 'A' + shift) % 26;
        } else if (clientIdToken[i] <= 'z') {
            token[i] = 'a' + (clientIdToken[i] - 'a' + shift) % 26;
        }
        else {
            return NULL;
        }
    }
    token[TOKEN_LEN] = '\0';
    return token;
}