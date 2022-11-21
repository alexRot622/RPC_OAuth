#include "auth.h"
#include "token.h"
#include "db.h"

oauth_response *
request_auth_1_svc(char **argp, struct svc_req *rqstp)
{
    static oauth_response result;

    result.requestToken = NULL;
    result.accessToken = NULL;
    if (!argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }
    if (!*argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }

    char *user_id = *argp;
    printf("BEGIN %s AUTHZ\n", user_id);

    int user_idx = find_user(user_id);
    if (user_idx < 0) {
        fprintf( stderr, "find_user(%s) returned %d.\n", user_id, user_idx);
        return &result;
    } else if (user_idx > 0) {
        result.status = PERMISSION_GRANTED;

        result.requestToken = generate_request_token(user_id);
        printf("  RequestToken = %s\n", result.requestToken);
        result.accessToken = generate_access_token(user_id);
        result.accessToken = generate_access_token(user_id);
        printf("  AccessToken = %s\n", result.accessToken);
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
