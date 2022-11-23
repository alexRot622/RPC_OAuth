/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _AUTH_H_RPCGEN
#define _AUTH_H_RPCGEN

#include <rpc/rpc.h>


#ifdef __cplusplus
extern "C" {
#endif


enum oauth_status {
	PERMISSION_GRANTED = 0,
	USER_NOT_FOUND = 1,
	REQUEST_DENIED = 2,
	PERMISSION_DENIED = 3,
	TOKEN_EXPIRED = 4,
	RESOURCE_NOT_FOUND = 5,
	OPERATION_NOT_PERMITTED = 6,
};
typedef enum oauth_status oauth_status;

enum action {
	READ = 0,
	INSERT = 1,
	MODIFY = 2,
	DELETE = 3,
	EXECUTE = 4,
};
typedef enum action action;

struct oauth_response {
	char *requestToken;
	char *accessToken;
	char *refreshToken;
	oauth_status status;
};
typedef struct oauth_response oauth_response;

struct s_val_act {
	action act;
	char *resource;
	char *token;
};
typedef struct s_val_act s_val_act;

struct s_req_token {
	char *id;
	char *token;
	s_val_act act;
	bool_t refresh;
};
typedef struct s_req_token s_req_token;

#define CHECKPROG 0x220811
#define CHECKVERS 1

#if defined(__STDC__) || defined(__cplusplus)
#define REQUEST_AUTH 1
extern  oauth_response * request_auth_1(char **, CLIENT *);
extern  oauth_response * request_auth_1_svc(char **, struct svc_req *);
#define REQUEST_TOKEN 2
extern  oauth_response * request_token_1(s_req_token *, CLIENT *);
extern  oauth_response * request_token_1_svc(s_req_token *, struct svc_req *);
#define VALIDATE_ACTION 3
extern  oauth_response * validate_action_1(s_req_token *, CLIENT *);
extern  oauth_response * validate_action_1_svc(s_req_token *, struct svc_req *);
#define APPROVE_TOKEN 4
extern  char ** approve_token_1(char **, CLIENT *);
extern  char ** approve_token_1_svc(char **, struct svc_req *);
extern int checkprog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#else /* K&R C */
#define REQUEST_AUTH 1
extern  oauth_response * request_auth_1();
extern  oauth_response * request_auth_1_svc();
#define REQUEST_TOKEN 2
extern  oauth_response * request_token_1();
extern  oauth_response * request_token_1_svc();
#define VALIDATE_ACTION 3
extern  oauth_response * validate_action_1();
extern  oauth_response * validate_action_1_svc();
#define APPROVE_TOKEN 4
extern  char ** approve_token_1();
extern  char ** approve_token_1_svc();
extern int checkprog_1_freeresult ();
#endif /* K&R C */

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_oauth_status (XDR *, oauth_status*);
extern  bool_t xdr_action (XDR *, action*);
extern  bool_t xdr_oauth_response (XDR *, oauth_response*);
extern  bool_t xdr_s_val_act (XDR *, s_val_act*);
extern  bool_t xdr_s_req_token (XDR *, s_req_token*);

#else /* K&R C */
extern bool_t xdr_oauth_status ();
extern bool_t xdr_action ();
extern bool_t xdr_oauth_response ();
extern bool_t xdr_s_val_act ();
extern bool_t xdr_s_req_token ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_AUTH_H_RPCGEN */
