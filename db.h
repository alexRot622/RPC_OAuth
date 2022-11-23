#ifndef OAUTH_DB_H
#define OAUTH_DB_H

#define USER_ID_FILE "userIDs.db"
#define USER_RESOURCE_FILE "resources.db"
#define USER_APPROVE_FILE "approvals.db"

int find_user(char *);
int find_resource(char *);
char* find_resource_permissions();

#endif //OAUTH_DB_H
