#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db.h"

int find_user(char *user_id) {
    FILE *db = fopen(USER_ID_FILE, "r");
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
