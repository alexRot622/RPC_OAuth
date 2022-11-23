#ifndef TEMA1_USER_H
#define TEMA1_USER_H

#include <string>
#include <unordered_map>
#include <utility>

using namespace std;

class User {
public:
    string accessToken;
    bool refresh = false;
    string refreshToken;
    int validity;
    unordered_map<string, string> permissions;

    User(string accessToken, unordered_map<string, string> permissions,
         int validity) : accessToken(move(accessToken)),
                         validity(validity),
                         permissions(move(permissions)) {}

    User(string accessToken, string refreshToken, int validity,
         const unordered_map<string, string> &permissions) : accessToken(move(accessToken)), refresh(true), validity(validity),
                                                             refreshToken(move(refreshToken)), permissions(permissions) {}

};


#endif //TEMA1_USER_H
