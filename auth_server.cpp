#include "auth.h"
#include "token.h"
#include "db.h"
#include "User.h"
#include "srv_params.h"

#include <unordered_map>
#include <string>
#include <regex>

std::unordered_map<std::string, std::pair<std::string, int>> requestTokens = {};
std::unordered_map<std::string, User *> users = {};

bool valid_signed_token(const std::string& requestToken);
bool valid_token(const std::string& token);
std::unordered_map<std::string, std::string> create_permission_map(std::string permStr);

std::string action_string(action act);

oauth_response *
request_auth_1_svc(char **argp, struct svc_req *rqstp)
{
    static oauth_response result;

    if (!argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }
    if (!*argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }

    // Make all address non-null so that RPC properly works
    result.accessToken = result.refreshToken = *argp;

    char *user_id = *argp;
    printf("BEGIN %s AUTHZ\n", user_id);

    int user_idx = find_user(user_id, user_id_file);
    if (user_idx < 0) {
        fprintf(stderr, "find_user(%s) returned %d.\n", user_id, user_idx);
        return &result;
    } else if (user_idx > 0) {
        result.status = PERMISSION_GRANTED;
        result.requestToken = generate_access_token(user_id);
        printf("  RequestToken = %s\n", result.requestToken);
        requestTokens[user_id] = std::make_pair(result.requestToken, validity);
        result.accessToken = result.refreshToken = result.requestToken;
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

    result.accessToken = generate_access_token(requestToken.data());
    printf("  AccessToken = %s\n", result.accessToken);
    User* user;
    if (argp->refresh) {
        result.refreshToken = generate_access_token(result.accessToken);
        printf("  RefreshToken = %s\n", result.refreshToken);
        user = new User(result.accessToken, result.refreshToken, validity, permissions);
    }
    else {
        // Set fields for RPC
        result.refreshToken = requestToken.data();
        user = new User(result.accessToken, validity, permissions);
    }

    users[std::string(user_id)] = user;

    result.status = PERMISSION_GRANTED;

    // Set fields for RPC
    result.requestToken = requestToken.data();
    return &result;
}

std::unordered_map<std::string, std::string> create_permission_map(std::string permStr) {
    char *token = strtok(permStr.data(), ",");
    std::unordered_map<std::string, std::string> permissions = {};
    while (token) {
        std::string filename = std::string(token);
        token = strtok(NULL, ",");
        std::string perms = std::string(token);
        token = strtok(NULL, ",");

        permissions.emplace(filename, perms);
    }
    return permissions;
}

bool valid_signed_token(const std::string& requestToken) {
    static std::string token_regex = "([a-zA-Z0-9]+,R?I?M?D?X?,)*&"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]";

    return std::regex_match(requestToken, std::regex(token_regex));
}

bool valid_token(const std::string& token) {
    static std::string token_regex = "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]"
                                     "[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]";

    return std::regex_match(token, std::regex(token_regex));
}

oauth_response *
validate_action_1_svc(s_req_token *argp, struct svc_req *rqstp)
{
    static oauth_response result;

    if (!argp) {
        result.status = USER_NOT_FOUND;
        return &result;
    }

    result.requestToken = argp->act.token;
    result.accessToken = argp->act.token;
    result.refreshToken = argp->act.token;

    char emptyString[1];
    emptyString[0] = '\0';
    if (!valid_token(argp->act.token)) {
        result.status = PERMISSION_DENIED;
        if (argp->act.resource == NULL)
            argp->act.resource = emptyString;
        if (argp->act.token == NULL)
            argp->act.token = emptyString;
        printf("DENY (%s,%s,%s,%d)\n", action_string(argp->act.act).data(),
               argp->act.resource, argp->act.token, 0);
        return &result;
    }

    std::string user_id;
    User *user;
    bool found = false;
    for (auto &it : users) {
        if (it.second->accessToken == argp->act.token) {
            user_id = it.first;
            result.accessToken = it.second->accessToken.data();
            result.refreshToken = it.second->refreshToken.data();
            user = it.second;
            found = true;
            break;
        }
    }

    if (!found) {
        result.status = PERMISSION_DENIED;
        if (argp->act.resource == NULL)
            argp->act.resource = emptyString;
        if (argp->act.token == NULL)
            argp->act.token = emptyString;
        printf("DENY (%s,%s,%s,%d)\n", action_string(argp->act.act).data(),
               argp->act.resource, argp->act.token, 0);
        return &result;
    }

    if (user->validity <= 0) {
        if (user->refresh) {
            result.accessToken = generate_access_token(user->refreshToken.data());
            result.refreshToken = generate_access_token(result.accessToken);

            user->accessToken = result.accessToken;
            argp->act.token = result.accessToken;
            user->refreshToken = result.refreshToken;
            printf("BEGIN %s AUTHZ REFRESH\n", user_id.data());
            printf("  AccessToken = %s\n", result.accessToken);
            printf("  RefreshToken = %s\n", result.refreshToken);

            user->validity = validity - 1;
        }
        else {
            result.status = TOKEN_EXPIRED;
            if (argp->act.resource == NULL)
                argp->act.resource = emptyString;
            if (argp->act.token == NULL)
                argp->act.token = emptyString;
            printf("DENY (%s,%s,,%d)\n", action_string(argp->act.act).data(),
                   argp->act.resource, 0);
            return &result;
        }
    }
    else {
        user->validity -= 1;
    }


    if (find_resource(argp->act.resource, resource_file) <= 0) {
        result.status = RESOURCE_NOT_FOUND;
        if (argp->act.resource == NULL)
            argp->act.resource = emptyString;
        if (argp->act.token == NULL)
            argp->act.token = emptyString;
        printf("DENY (%s,%s,%s,%d)\n", action_string(argp->act.act).data(),
               argp->act.resource, argp->act.token, user->validity);
        return &result;
    }

    if (user->permissions.find(argp->act.resource) == user->permissions.end()) {
        result.status = OPERATION_NOT_PERMITTED;
        if (argp->act.resource == NULL)
            argp->act.resource = emptyString;
        if (argp->act.token == NULL)
            argp->act.token = emptyString;
        printf("DENY (%s,%s,%s,%d)\n", action_string(argp->act.act).data(),
               argp->act.resource, argp->act.token, user->validity);
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
        default: {
            result.status = OPERATION_NOT_PERMITTED;
            return &result;
        }
    }

    for (char &c : permString) {
        if (c == lookup) {
            result.status = PERMISSION_GRANTED;
            if (argp->act.resource == NULL)
                argp->act.resource = emptyString;
            if (argp->act.token == NULL)
                argp->act.token = emptyString;
            printf("PERMIT (%s,%s,%s,%d)\n", action_string(argp->act.act).data(),
                   argp->act.resource, argp->act.token, user->validity);
            return &result;
        }
    }

    result.status = OPERATION_NOT_PERMITTED;
    if (argp->act.resource == NULL)
        argp->act.resource = emptyString;
    if (argp->act.token == NULL)
        argp->act.token = emptyString;
    printf("DENY (%s,%s,%s,%d)\n", action_string(argp->act.act).data(),
           argp->act.resource, argp->act.token, user->validity);
    return &result;
}

std::string action_string(action act) {
    switch (act) {
        case READ: {
            return "READ";
        }
        case INSERT: {
            return "INSERT";
        }
        case MODIFY: {
            return "MODIFY";
        }
        case DELETE: {
            return "DELETE";
        }
        case EXECUTE: {
            return "EXECUTE";
        }
        default: {
            return "";
        }
    }
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
            found = true;
            break;
        }
    }

    if (!found) {
        return &result;
    }

    char *permissions = find_resource_permissions(approve_file);
    if (permissions == NULL) {
        return &result;
    }
    if (strlen(permissions) == 0) {
        result = (char *) calloc(strlen(*token) + 1, 1);
        strcpy(result, *token);
    }
    else {
        result = (char *) calloc(strlen(*token) + strlen(permissions) + 2, 1);
        sprintf(result, "%s&%s", permissions, *token);
    }

    return &result;
}
