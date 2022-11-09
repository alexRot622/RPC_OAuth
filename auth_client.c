/*
 * This is sample code generated by rpcgen.
 * These are only templates and you can use them
 * as a guideline for developing your own functions.
 */

#include "auth.h"


void
checkprog_1(char *host)
{
	CLIENT *clnt;
	oauth_response  *result_1;
	char * request_auth_1_arg;
	oauth_response  *result_2;
	s_req_token  request_token_1_arg;
	oauth_response  *result_3;
	s_val_act  validate_action_1_arg;
	char * *result_4;
	char * approve_token_1_arg;

#ifndef	DEBUG
	clnt = clnt_create (host, CHECKPROG, CHECKVERS, "udp");
	if (clnt == NULL) {
		clnt_pcreateerror (host);
		exit (1);
	}
#endif	/* DEBUG */

	result_1 = request_auth_1(&request_auth_1_arg, clnt);
	if (result_1 == (oauth_response *) NULL) {
		clnt_perror (clnt, "call failed");
	}
	result_2 = request_token_1(&request_token_1_arg, clnt);
	if (result_2 == (oauth_response *) NULL) {
		clnt_perror (clnt, "call failed");
	}
	result_3 = validate_action_1(&validate_action_1_arg, clnt);
	if (result_3 == (oauth_response *) NULL) {
		clnt_perror (clnt, "call failed");
	}
	result_4 = approve_token_1(&approve_token_1_arg, clnt);
	if (result_4 == (char **) NULL) {
		clnt_perror (clnt, "call failed");
	}
#ifndef	DEBUG
	clnt_destroy (clnt);
#endif	 /* DEBUG */
}


int
main (int argc, char *argv[])
{
	char *host;

	if (argc < 2) {
		printf ("usage: %s server_host\n", argv[0]);
		exit (1);
	}
	host = argv[1];
	checkprog_1 (host);
exit (0);
}