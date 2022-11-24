/*
 * This is sample code generated by rpcgen.
 * These are only templates and you can use them
 * as a guideline for developing your own functions.
 */

#include "auth.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char *status_string(oauth_status status);

void
checkprog_1(char *host, char *filename)
{
	CLIENT *clnt;
	void *result;
	char *request_auth;
	s_req_token request_token;

#ifndef	DEBUG
	clnt = clnt_create (host, CHECKPROG, CHECKVERS, "udp");
	if (clnt == NULL) {
		clnt_pcreateerror (host);
		exit (1);
	}
#endif	/* DEBUG */

    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "%s not found\n", filename);
        return;
    }

    char line[256];
    char *token;

    char **users = calloc(256, sizeof(char *));
    char **accessTokens = calloc(256, sizeof(char *));
    char **refreshTokens = calloc(256, sizeof(char *));
    int nUsers = 0;

    while (fgets(line, 256, file)) {
        token = strtok(line, ",\n");
        char *user_id = calloc(strlen(token) + 1, 1);
        strncpy(user_id, token, strlen(token));

        token = strtok(NULL, ",\n");
        char *command = calloc(strlen(token) + 1, 1);
        strncpy(command, token, strlen(token));

        token = strtok(NULL, ",\n");
        char *arg = calloc(strlen(token) + 1, 1);
        strncpy(arg, token, strlen(token));

        if (strcmp(command, "REQUEST") == 0) {
            if (strcmp(arg, "0") == 0) {
                request_token.refresh = 0;
            }
            else if (strcmp(arg, "1") == 0) {
                request_token.refresh = 1;
            }
            else {
                // TODO: PRINT ERROR
            }

            request_auth = user_id;
            oauth_response *response = request_auth_1(&request_auth, clnt);
            if (response == NULL) {
                fprintf(stderr, "RESULT NULL1\n");
                clnt_perror(clnt, "call failed");
                continue;
            }

            if (response->status) {
                printf("%s\n", status_string(response->status));
                continue;
            }

            char *requestToken = calloc(strlen(response->requestToken), 1);
            strcpy(requestToken, response->requestToken);
            char **signed_token = approve_token_1(&requestToken, clnt);
            if (strcmp(requestToken, *signed_token) == 0) {
                // TODO: print not signed or smth
                // TODO: free memory
                printf("REQUEST_DENIED\n");
                continue;
            }

            request_token.token = *signed_token;
            request_token.id = user_id;

            // TODO: RPC is weird
            request_token.act.token = calloc(1, 1);
            request_token.act.act = 1;
            request_token.act.resource = calloc(1, 1);

            response = request_token_1(&request_token, clnt);
            free(request_token.act.token);
            free(request_token.act.resource);
            if (response == NULL) {
                fprintf(stderr, "RESULT NULL2\n");
                clnt_perror(clnt, "call failed");
                continue;
            }

            if (response->status) {
                printf("%s\n", status_string(response->status));
                continue;
            }

            int pos = -1;
            for (int i = 0; i < nUsers && pos < 0; i++) {
                if (strcmp(users[i], user_id) == 0) {
                    pos = i;
                }
            }

            if (pos < 0) {
                pos = nUsers;
                nUsers++;
            }
            if (!users[pos])
                users[pos] = calloc(32, 1);
            strcpy(users[pos], user_id);

            if (!accessTokens[pos])
                accessTokens[pos] = calloc(32, 1);
            strcpy(accessTokens[pos], response->accessToken);

            if (request_token.refresh) {
                if (!refreshTokens[pos])
                    refreshTokens[pos] = calloc(32, 1);
                strcpy(refreshTokens[pos], response->refreshToken);
            }

            printf("%s -> %s", requestToken, response->accessToken);
            if (request_token.refresh) {
                printf(",%s", response->refreshToken);
            }
            printf("\n");

            free(requestToken);
        }
        else {
            // Operation
            action act;
            if (strcmp(command, "READ") == 0) {
                act = READ;
            }
            else if (strcmp(command, "INSERT") == 0) {
                act = INSERT;
            }
            else if (strcmp(command, "MODIFY") == 0) {
                act = MODIFY;
            }
            else if (strcmp(command, "DELETE") == 0) {
                act = DELETE;
            }
            else if (strcmp(command, "EXECUTE") == 0) {
                act = EXECUTE;
            }
            else {
                // TODO: PRINT ERROR
                break;
            }

            request_token.act.act = act;
            request_token.act.token = NULL;
            request_token.act.resource = arg;

            int found = 0;
            int id = 0;
            for (int i = 0; i < nUsers && !found; i++) {
                if (strcmp(users[i], user_id) == 0) {
                    request_token.act.token = accessTokens[i];
                    id = i;
                    found = 1;
                }
            }


            // TODO: RPC is weird
            request_token.id = calloc(1, 1);
            request_token.token = calloc(1, 1);
            if (!found)
                request_token.act.token = calloc(1, 1);

            result = validate_action_1(&request_token, clnt);
            free(request_token.id);
            free(request_token.token);
            if (!found)
                free(request_token.act.token);
            if (result == (oauth_response *) NULL) {
                clnt_perror(clnt, "call failed");
            }

            oauth_response *response = (oauth_response *) (result);
            printf("%s\n", status_string(response->status));
            if (strcmp(accessTokens[id], response->accessToken) != 0) {
                strcpy(accessTokens[id], response->accessToken);
                strcpy(refreshTokens[id], response->refreshToken);
            }
        }
    }

    for (int i = 0; i < nUsers; i++) {
        if (users[i])
            free(users[i]);
        if (accessTokens[i])
            free(accessTokens[i]);
        if (refreshTokens[i])
            free(refreshTokens[i]);
    }
    free(users);
    free(accessTokens);
    free(refreshTokens);

#ifndef	DEBUG
	clnt_destroy (clnt);
#endif	 /* DEBUG */
}

char *status_string(oauth_status status) {
    switch (status) {
        case PERMISSION_GRANTED: {
            return "PERMISSION_GRANTED";
        }
        case USER_NOT_FOUND: {
            return "USER_NOT_FOUND";
        }
        case REQUEST_DENIED: {
            return "REQUEST_DENIED";
        }
        case PERMISSION_DENIED: {
            return "PERMISSION_DENIED";
        }
        case TOKEN_EXPIRED: {
            return "TOKEN_EXPIRED";
        }
        case RESOURCE_NOT_FOUND: {
            return "RESOURCE_NOT_FOUND";
        }
        case OPERATION_NOT_PERMITTED: {
            return "OPERATION_NOT_PERMITTED";
        }
        default:
            return NULL;
    }
}

int
main (int argc, char *argv[])
{
	char *host;

	if (argc < 3) {
		printf ("usage: %s server_host client_input\n", argv[0]);
		exit (1);
	}
	host = argv[1];
	checkprog_1(host, argv[2]);
exit (0);
}
