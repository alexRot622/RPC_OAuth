
# This is a template Makefile generated by rpcgen

# Parameters

CLIENT = auth_client
SERVER = auth_server

SOURCES_CLNT.c =
SOURCES_CLNT.h =
SOURCES_SVC.c =
SOURCES_SVC.h =
SOURCES.x = auth.x

TARGETS_SVC.c = auth_svc.c auth_server.cpp auth_xdr.c db.cpp
TARGETS_CLNT.c = auth_clnt.c auth_client.c auth_xdr.c
TARGETS = auth.h auth_xdr.c auth_clnt.c auth_svc.c auth_client.c auth_server.cpp

OBJECTS_CLNT = $(SOURCES_CLNT.c:%.c=%.o) $(TARGETS_CLNT.c:%.c=%.o)
OBJECTS_SVC = $(SOURCES_SVC.c:%.c=%.o) $(TARGETS_SVC.c:%.c=%.o)
# Compiler flags

CFLAGS += -g -I /usr/include/tirpc
CPPFLAGS += -g -I /usr/include/tirpc
LDLIBS += -lnsl -ltirpc
RPCGENFLAGS =

# Targets

all : $(CLIENT) $(SERVER)

$(TARGETS) : $(SOURCES.x)
	rpcgen $(RPCGENFLAGS) $(SOURCES.x)

$(OBJECTS_CLNT) : $(SOURCES_CLNT.c) $(SOURCES_CLNT.h) $(TARGETS_CLNT.c)

$(OBJECTS_SVC) : $(SOURCES_SVC.c) $(SOURCES_SVC.h) $(TARGETS_SVC.c)

$(CLIENT) : $(OBJECTS_CLNT)
	$(LINK.c) -o $(CLIENT) $(OBJECTS_CLNT) $(LDLIBS)

$(SERVER) : $(OBJECTS_SVC)
	$(LINK.cpp) -o $(SERVER) $(OBJECTS_SVC) $(LDLIBS)

 clean:
	 $(RM) core Makefile.auth $(OBJECTS_CLNT) $(OBJECTS_SVC) $(CLIENT) $(SERVER)