#ifndef COMMON_H_
#define COMMON_H_

#include <libssh/libssh.h>
#include <pthread.h>

/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/* A userdata struct for session. */
struct session_data_struct 
{
    // /* pid of the child process the channel will spawn. */
    // pid_t pid;
    char *rhost;
    int rport;
    pthread_t tid;
    /* Pointer to the channel the session will allocate. */
    ssh_session client_session;
    ssh_channel server_channel;
    ssh_channel client_channel;
    int chan_id;
    int auth_attempts;
    int authenticated;
    /* Event which is used to poll the above descriptors. */
    ssh_event server_event;
    ssh_event client_event;
    // /* For communication with the child process. */
    // socket_t child_stdin;
    // socket_t child_stdout;
    // /* Only used for subsystem and exec requests. */
    // socket_t child_stderr;
    int shell;
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *arg1;                   /* arg1 */
  char **strings;               /* [string…] */
  int verbosity, rport, lport;
  char *rhost, *hostkey, *dsakey, *rsakey, *ecdsakey;
};

// int verify_knownhost(ssh_session session);
ssh_session connect_ssh(const char *hostname, const char *user, int port, int verbosity);

#endif /* COMMON_H_ */