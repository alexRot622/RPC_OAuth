#include "auth.h"
#include "token.h"
#include "db.h"

oauth_response *
request_auth_1_svc(char **argp, struct svc_req *rqstp)
{
	static oauth_response result;

    result.token = NULL;
    if (!argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }
    if (!*argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }

    char *user_id = *argp;
    int user_idx = find_user(user_id);

    if (user_idx < 0) {
        fprintf( stderr, "find_user(%s) returned %d.\n", user_id, user_idx);
        return &result;
    } else if (user_idx > 0) {
        result.status = 0;
        result.token = generate_access_token(user_id);
    } else {
        result.status = USER_NOT_FOUND;
    }

	return &result;
}

oauth_response *
request_token_1_svc(s_req_token *argp, struct svc_req *rqstp)
{
	static oauth_response  result;

	/*
	 * insert server code here
	 */

	return &result;
}

oauth_response *
validate_action_1_svc(s_val_act *argp, struct svc_req *rqstp)
{
	static oauth_response  result;

	/*
	 * insert server code here
	 */

	return &result;
}

char **
approve_token_1_svc(char **argp, struct svc_req *rqstp)
{
	static char * result;

	/*
	 * insert server code here
	 */

	return &result;
}
