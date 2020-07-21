#ifndef COMMON_H_
#define COMMON_H_

#include <libssh/libssh.h>

/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

// typedef int (*ssh_auth_password_callback) (struct ssh_cms_struct *c2m, struct ssh_cms_struct *m2s, const char *user, const char *password,
// 		void *userdata);

/* A userdata struct for session. */
struct session_data_struct 
{
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
    /* For communication with the child process. */
    socket_t child_stdin;
    socket_t child_stdout;
    /* Only used for subsystem and exec requests. */
    socket_t child_stderr;
    int shell;
};


// /* A userdata struct for channel. */
// struct channel_data_struct 
// {
//     // /* pid of the child process the channel will spawn. */
//     // pid_t pid;
//     /* For communication with the child process. */
//     socket_t child_stdin;
//     socket_t child_stdout;
//     /* Only used for subsystem and exec requests. */
//     socket_t child_stderr;
//     // /* Event which is used to poll the above descriptors. */
//     ssh_event event;
//     // ssh_event client_event;
// };



// /* 
// * Client-MiTM-Server Struct
// */
// struct ssh_cms_struct 
// {
//     ssh_session session;
//     ssh_channel chan;
//     int rc;
//     int auth;
//     int shell;
//     int sftp;
//     int scp;
// };

int verify_knownhost(ssh_session session);
ssh_session connect_ssh(const char *hostname, const char *user, int verbosity);

// static void handle_session(ssh_event event, ssh_session session);

//static int auth_password(struct ssh_cms_struct *c2m, struct ssh_cms_struct *m2s, const char *user, const char *pass, void *userdata);

#endif /* COMMON_H_ */