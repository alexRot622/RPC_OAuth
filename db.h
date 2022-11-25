#ifndef OAUTH_DB_H
#define OAUTH_DB_H

int find_user(char *, char *);
int find_resource(char *, char *);
char* find_resource_permissions(char *);

#endif //OAUTH_DB_H
