enum oauth_status {
    PERMISSION_GRANTED = 0,
    USER_NOT_FOUND = 1,
    REQUEST_DENIED = 2,
    PERMISSION_DENIED = 3,
    TOKEN_EXPIRED = 4,
    RESOURCE_NOT_FOUND = 5,
    OPERATION_NOT_PERMITTED = 6
};

enum action {
    READ = 0,
    INSERT = 1,
    MODIFY = 2,
    DELETE = 3,
    EXECUTE = 4
};

struct oauth_response {
    string requestToken<>;
    string accessToken<>;
    oauth_status status;
};

struct s_req_token {
    string id<>;
    string token<>;
    bool renew;
};

struct s_val_act {
    action act;
    string resource<>;
    string token<>;
};

program CHECKPROG {
    version CHECKVERS {
        oauth_response REQUEST_AUTH(string) = 1;
        oauth_response REQUEST_TOKEN(s_req_token) = 2;
        oauth_response VALIDATE_ACTION(s_val_act) = 3;
        string APPROVE_TOKEN(string) = 4;
    } = 1;
} = 0x220811;