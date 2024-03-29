#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db.h"
#include "stdio.h"

#include <unordered_map>
#include <string>

std::unordered_map<std::string, std::string> permissions = {};

int find_user(char *user_id, char *user_id_file) {
    FILE *db = fopen(user_id_file, "r");
    if (!db)
        return -1;
    char s_num[16];
    long db_num;

    fgets(s_num, 16, db);
    if (!*s_num) {
        return -1;
    }
    db_num = strtol(s_num, NULL, 0);
    if (db_num <= 0) {
        return -2;
    }

    char read_id[20];
    for (int i = 0; i < db_num; i++) {
        fgets(read_id, 20, db);
        read_id[15] = 0;
        if (strcmp(read_id, user_id) == 0) {
            fclose(db);
            return i + 1;
        }
    }

    fclose(db);
    return 0;
}

int find_resource(char *resource, char *resource_file) {
    FILE *db = fopen(resource_file, "r");
    if (!db)
        return -1;
    char r_num[16];
    long db_num;

    fgets(r_num, 16, db);
    if (!*r_num) {
        return -1;
    }
    db_num = strtol(r_num, NULL, 0);
    if (db_num <= 0) {
        return -2;
    }

    char db_resource[64];
    for (int i = 0; i < db_num; i++) {
        fgets(db_resource, 64, db);
        int len = strlen(db_resource);
        if (db_resource[len - 1] == '\n')
            db_resource[len - 1] = '\0';
        if (strcmp(db_resource, resource) == 0) {
            fclose(db);
            return i + 1;
        }
    }

    fclose(db);
    return 0;
}

int load_resource_permissions(char *approve_file) {
    static FILE *db = NULL;
    static char line[256];

    if (db == NULL) {
        db = fopen(approve_file, "r");
    }

    if (!fgets(line, 256, db)) {
        return -1;
    }

    char *token = strtok(line, ",");

    permissions = {};
    while (token) {
        std::string filename(token);
        token = strtok(NULL, ",");

        int len = strlen(token);
        if (token[len - 1] == '\n')
            token[len - 1] = '\0';
        std::string perms(token);

        token = strtok(NULL, ",");

        if (filename == "*") {
            break;
        }

        permissions.emplace(filename, perms);
    }

    return 0;
}

char *find_resource_permissions(char *approve_file) {
    if (load_resource_permissions(approve_file))
        return NULL;

    std::string perms;
    for (auto &it : permissions) {
        perms += it.first + "," + it.second + ",";
    }

    return strdup(perms.data());
}

