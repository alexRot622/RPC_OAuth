#include "auth.h"
#include "token.h"
#include "db.h"
#include "User.h"

#include <unordered_map>
#include <string>
#include <regex>

std::unordered_map<std::string, std::pair<std::string, int>> requestTokens = {};
std::unordered_map<std::string, User *> users = {};
int validity = 2;

bool valid_signed_token(const std::string& requestToken);
bool valid_token(const std::string& token);
std::unordered_map<std::string, std::string> create_permission_map(std::string permStr);

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
        result.requestToken = generate_access_token(user_id);
        printf("  RequestToken = %s\n", result.requestToken);
        requestTokens.emplace(user_id, std::make_pair(result.requestToken, validity));
    } else {
        result.status = USER_NOT_FOUND;
    }

    return &result;
}

oauth_response *
request_token_1_svc(s_req_token *argp, struct svc_req *rqstp)
{
    static oauth_response result;

    result.requestToken = NULL;
    result.accessToken = NULL;
    if (!argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }

    char *user_id = argp->id;
    if (requestTokens.count(user_id) == 0) {
        result.status = USER_NOT_FOUND;
        return &result;
    }

    // TODO: is it ok to compare C++ string with C char*?
    if (!valid_signed_token(argp->token)) {
        result.status = REQUEST_DENIED;
        return &result;
    }

    char *token = strtok(argp->token, "&");
    std::string permissionString = std::string(token);
    token = strtok(NULL, "&");
    std::string requestToken = std::string(token);

    if (requestTokens[user_id].first != requestToken) {
        result.status = REQUEST_DENIED;
        return &result;
    }

    std::unordered_map<std::string, std::string> permissions = create_permission_map(permissionString);

    result.accessToken = generate_access_token(argp->token);
    printf("  AccessToken = %s\n", result.accessToken);
    result.refreshToken = generate_access_token(result.accessToken);

    User* user = new User(result.accessToken, result.refreshToken, validity, permissions);
    users.emplace(std::string(user_id), user);
    printf("  RefreshToken = %s\n", result.accessToken);

    return &result;
}

std::unordered_map<std::string, std::string> create_permission_map(std::string permStr) {
    char *token = strtok(permStr.data(), "/");
    std::unordered_map<std::string, std::string> permissions = {};
    while (token) {
        std::string perms = std::string(token);
        token = strtok(NULL, "/");
        std::string filename = std::string(token);
        token = strtok(NULL, "/");

        permissions.emplace(filename, perms);
    }
    return permissions;
}

bool valid_signed_token(const std::string& requestToken) {
    static std::string token_regex = "(R?I?M?D?X?/[a-zA-Z0-9]+/)*&"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]";

    return std::regex_match(requestToken, std::regex(token_regex));
}

bool valid_token(const std::string& token) {
    static std::string token_regex = "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]";

    return std::regex_match(token, std::regex(token_regex));
}

oauth_response *
validate_action_1_svc(s_req_token *argp, struct svc_req *rqstp)
{
    static oauth_response result;

    result.requestToken = NULL;
    result.accessToken = NULL;
    if (!argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }

    if (!valid_token(argp->act.token)) {
        result.status = PERMISSION_DENIED;
        return &result;
    }

    // TODO: is it ok to compare C++ string with C char*?
    std::string user_id;
    User *user;
    bool found = false;
    for (auto &it : users) {
        if (it.second->accessToken == argp->act.token) {
            user_id = it.first;
            user = it.second;
            found = true;
            break;
        }
    }

    if (!found) {
        result.status = PERMISSION_DENIED;
        return &result;
    }


    if (user->validity < 0) {
        result.status = TOKEN_EXPIRED;
        return &result;
    }

    if (find_resource(argp->act.resource) <= 0) {
        result.status = RESOURCE_NOT_FOUND;
        return &result;
    }

    if (user->permissions.find(argp->act.resource) == user->permissions.end()) {
        result.status = OPERATION_NOT_PERMITTED;
        return &result;
    }

    std::string permString = user->permissions.at(argp->act.resource);
    char lookup;
    switch (argp->act.act) {
        case READ: lookup = 'R'; break;
        case INSERT: lookup = 'I'; break;
        case MODIFY: lookup = 'M'; break;
        case DELETE: lookup = 'D'; break;
        case EXECUTE: lookup = 'X'; break;
        default: break;//TODO PRINT ERROR
    }

    for (char &c : permString) {
        if (c == lookup) {
            result.status = PERMISSION_GRANTED;
            return &result;
        }
    }

    result.status = OPERATION_NOT_PERMITTED;
    return &result;
}

char **
approve_token_1_svc(char **token, struct svc_req *rqstp)
{
    static char *result = NULL;

    if (token == NULL) {
        return &result;
    }
    if (*token == NULL) {
        return &result;
    }

    result = *token;

    bool found = false;
    for (auto &it : requestTokens) {
        if (it.second.first == *token) {
            //TODO: validity?
            found = true;
            break;
        }
    }

    if (!found) {
        return &result;
    }

    char *permissions = find_resource_permissions();
    if (permissions == NULL) {
        return &result;
    }
    result = (char *) calloc(strlen(*token) + strlen(permissions) + 2, 1);
    sprintf(result, "%s&%s", permissions, *token);

    return &result;
}
