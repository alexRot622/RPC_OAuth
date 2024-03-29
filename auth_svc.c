/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "auth.h"
#include "srv_params.h"
#include <stdio.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef SIG_PF
#define SIG_PF void(*)(int)
#endif

static void
checkprog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		char *request_auth_1_arg;
		s_req_token request_token_1_arg;
		s_req_token validate_action_1_arg;
		char *approve_token_1_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply (transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;

	case REQUEST_AUTH:
		_xdr_argument = (xdrproc_t) xdr_wrapstring;
		_xdr_result = (xdrproc_t) xdr_oauth_response;
		local = (char *(*)(char *, struct svc_req *)) request_auth_1_svc;
		break;

	case REQUEST_TOKEN:
		_xdr_argument = (xdrproc_t) xdr_s_req_token;
		_xdr_result = (xdrproc_t) xdr_oauth_response;
		local = (char *(*)(char *, struct svc_req *)) request_token_1_svc;
		break;

	case VALIDATE_ACTION:
		_xdr_argument = (xdrproc_t) xdr_s_req_token;
		_xdr_result = (xdrproc_t) xdr_oauth_response;
		local = (char *(*)(char *, struct svc_req *)) validate_action_1_svc;
		break;

	case APPROVE_TOKEN:
		_xdr_argument = (xdrproc_t) xdr_wrapstring;
		_xdr_result = (xdrproc_t) xdr_wrapstring;
		local = (char *(*)(char *, struct svc_req *)) approve_token_1_svc;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	return;
}

char *user_id_file;
char *resource_file;
char *approve_file;
int validity;
int
main (int argc, char **argv)
{
	register SVCXPRT *transp;

    if (argc < 5) {
        printf ("usage: %s user_file resource_file approval_file validity\n", argv[0]);
        exit (1);
    }

    user_id_file = argv[1];
    resource_file = argv[2];
    approve_file = argv[3];
    validity = strtol(argv[4], NULL, 0);

    setbuf(stdout, NULL);

	pmap_unset (CHECKPROG, CHECKVERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, CHECKPROG, CHECKVERS, checkprog_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (CHECKPROG, CHECKVERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, CHECKPROG, CHECKVERS, checkprog_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (CHECKPROG, CHECKVERS, tcp).");
		exit(1);
	}

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}
