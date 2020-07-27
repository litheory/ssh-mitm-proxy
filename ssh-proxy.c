#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include <sys/ioctl.h>
// #include <sys/select.h>
#include <sys/wait.h>
// #include <sys/time.h>
// #include <sys/types.h>
// #include <sys/stat.h>


// #ifdef HAVE_ARGP_H
#include <argp.h>
// #endif
#include <unistd.h>
// #include <pty.h>
// #include <utmp.h>
#include <signal.h>
#include <errno.h>
// #include <fcntl.h>
#include <pthread.h>
// #include <poll.h>
// #include <select.h>

#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include "common.h"

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

#define BUF_SIZE 4096
#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)
#define SFTP_SERVER_PATH "/usr/lib/sftp-server"

#define REMOTE_HOST "10.100.1.33"
#define REMOTE_PORT 22

// #ifdef HAVE_ARGP_H
const char *argp_program_version = "SSH-Proxy1.1 libssh "
SSH_STRINGIFY(LIBSSH_VERSION);
const char *argp_program_bug_address = "<dhakkan@foxmail.com>";

/* Program documentation. */
static char doc[] = "ssh-proxy --  an intercepting (mitm) proxy server for security audits.";
/* A description of the arguments we accept. */
static char args_doc[] = "";

/* The options we understand. */
static struct argp_option options[] = {
    {
        .name  = "verbosity",
        .key   = 'v',
        .arg   = "VERBOSE",
        .flags = 0,
        .doc   = "Produce verbose output [0-4]." 
                 "default 0",
        .group = 0
    },
    {
        .name  = "lport",
        .key   = 'l',
        .arg   = "PORT",
        .flags = 0,
        .doc   = "Set the local port to bind." 
                 "default 2222",
        .group = 0
    },
    {
        .name  = "rhost",
        .key   = 't',
        .arg   = "HOST",
        .flags = 0,
        .doc   = "Set the proxy destination remote host",
        .group = 0
    },
    {
        .name  = "rport",
        .key   = 'p',
        .arg   = "PORT",
        .flags = 0,
        .doc   = "Set the proxy destination remote port."
                 "defualt 22",
        .group = 0
    },
    {
        .name  = "hostkey",
        .key   = 'k',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set a host key.  Can be used multiple times."
                 "default /etc/ssh/ssh_host_ed25519_key",
        .group = 0
    },
    {
        .name  = "dsakey",
        .key   = 'd',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the dsa key."
                 "default /etc/ssh/ssh_dsa_key",
        .group = 0
    },
    {
        .name  = "rsakey",
        .key   = 'r',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the rsa key."
                 "default /etc/ssh/ssh_rsa_key",
        .group = 0
    },
    {
        .name  = "ecdsakey",
        .key   = 'e',
        .arg   = "FILE",
        .flags = 0,
        .doc   = "Set the ecdsa key."
                 "default /etc/ssh/ssh_ecdsa_key",
        .group = 0
    },
    {0}
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
    /* Get the input argument from argp_parse, which we
     * know is a pointer to our arguments structure. */
    struct arguments *args = state->input;
    static int hostkey_set = 0, rsa_set = 0, dsa_set = 0, ecdsa_set = 0;
    static int rhost_set = 0, rport_set = 0, lport_set = 0, verbosity_set;

    switch (key) {
        case 'k':
            args->hostkey = arg;
            /* We can't track the types of keys being added with this
               option, so let's ensure we keep the keys we're adding
               by just not setting the default keys */
            hostkey_set = 1;
            break;
        case 'd':
            args->dsakey = arg;
            dsa_set = 1;
            break;
        case 'r':
            args->rsakey = arg;
            rsa_set = 1;
            break;
        case 'e':
            args->ecdsakey = arg;
            ecdsa_set = 1;
            break;
        case 'v':
            args->verbosity = atoi(arg);
            verbosity_set = 1;
            break;
        case 'l':
            args->lport = atoi(arg);
            lport_set = 1;
            break;
        case 'p':
            args->rport = atoi(arg);
            rport_set = 1;
            break;
        case 't':
            args->rhost = arg;
            rhost_set = 1;
            break;
        case ARGP_KEY_NO_ARGS:
            printf("[OPTION] ARGP_KEY_NO_ARGS\n");
            argp_usage(state);
        case ARGP_KEY_ARG:
            /* Here we know that state->arg_num == 0, since we
                force argument parsing to end before any more arguments can
                get here. */
            args->arg1 = arg;
            /* Now we consume all the rest of the arguments.
                state->next is the index in state->argv of the
                next argument to be parsed, which is the first string
                we’re interested in, so we can just use
                &state->argv[state->next] as the value for
                arguments->strings. 

                In addition, by setting state->next to the end
                of the arguments, we can force argp to stop parsing here and
                return. */
            args->strings = &state->argv[state->next];
            state->next = state->argc;
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 1) {
                /* Not enough arguments. */
                printf("[OPTION] Not enough arguments\n");
                argp_usage (state);
            }
            if (!lport_set)
            {
                args->lport = 2222;
                printf("[OPTION] Server listen on local port 2222 default\n");
            }
            if (!rport_set)
            {
                args->rport = 22;
                printf("[OPTION] Client connect remote SSH SERVER port 22 default\n");
            }
            if (!verbosity_set)
            {
                args->verbosity = 0;
                printf("[OPTION] Verbosity set to 0 default\n");
            }
            if (!hostkey_set)
            {
                args->hostkey = KEYS_FOLDER "ssh_host_ed25519_key";
                // ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, KEYS_FOLDER "ssh_host_ed25519_key");
            }
           
            if (!rsa_set) 
            {
                args->rsakey = KEYS_FOLDER "ssh_host_rsa_key";
                printf("[OPTION] Server load rsa key %s default\n", args->rsakey);
                // ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");
            }
            if (!dsa_set) 
            {
                args->dsakey = KEYS_FOLDER "ssh_host_dsa_key";
                // ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
            }
            if (!ecdsa_set) 
            {
                args->ecdsakey = KEYS_FOLDER "ssh_host_ecdsa_key";
                // ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, KEYS_FOLDER "ssh_host_ecdsa_key");
            }
            printf("[OPTION] lport = %d, rhost = %s, rport = %d, verbosity = %d\n", args->lport, args->rhost, args->rport, args->verbosity);
            printf("[OPTION] hostkey = %s, rsakey = %s, dsakey = %s, ecdsakey = %s\n", args->hostkey, args->rsakey, args->dsakey, args->ecdsakey);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, args_doc, doc};

// #endif /* HAVE_ARGP_H */

static int auth_none(ssh_session session, const char *user, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    int rc;
    char *banner;

    // printf("[CALLBACK] auth_none\n");
    if(ssh_is_connected(sdata->client_session))
    {
        rc = ssh_userauth_none(sdata->client_session, user);
        /* The SSH server might send a banner, retrieve with ssh_get_issue_banner(), then display to the user */
        banner = ssh_get_issue_banner(sdata->client_session);
        if(banner)
        {
            printf("%s\n", banner);
            free(banner);
        }
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: Client session is not connected\n");
    }
    return rc;
}

static int auth_password(ssh_session session, const char *user, const char *pass, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    int rc;

    // printf("[CALLBACK] auth_password\n");
    if(ssh_is_connected(sdata->client_session))
    {
        rc = ssh_userauth_password(sdata->client_session, user, pass);
        printf("[CLIENT] > Try auth with Username:%s and Password:%s\n", user, pass);
        if (rc == SSH_AUTH_SUCCESS)
        {
            sdata->authenticated = 1;
            printf("[CLIENT] Authentication successed (password), user:%s\n", user);

            return SSH_AUTH_SUCCESS;
        }
        sdata->auth_attempts++;
        printf("[CLIENT] * Have tried %d auth\n", sdata->auth_attempts);
        return SSH_AUTH_DENIED;
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: Client session is not connected\n");
    }

}

static ssh_channel channel_open_request_session(ssh_session session, void *userdata) 
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    int rc;    

    // printf("[CALLBACK] channel_open_request_session\n");
    sdata->chan_id++;
    if(ssh_is_connected(sdata->client_session))
    {
        sdata->server_channel = ssh_channel_new(session);
        printf("[SERVER] < channel %d: new [server-session]\n", sdata->chan_id);
        
        sdata->client_channel = ssh_channel_new(sdata->client_session);
        printf("[CLIENT] > channel %d: new [client-session]\n", sdata->chan_id);

        rc = ssh_channel_open_session(sdata->client_channel);
        printf("[CLIENT] > channel %d: send open\n", sdata->chan_id);
        if(rc != SSH_OK)
        {
            fprintf(stderr,"[CLIENT] error: open session failed : %s\n",ssh_get_error(sdata->client_channel));
            ssh_channel_close(sdata->client_channel);
            return NULL;
        }

        printf("[CLIENT] Entering interactive session\n");
        return sdata->server_channel;
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: Client session is not connected\n");
    }
}

static void channel_eof(ssh_session session, ssh_channel channel, void *userdata)
{    
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    (void) channel;
    int rc;
    
    // printf("[CALLBACK] channel_eof\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_send_eof(sdata->client_channel);
        if(rc != SSH_OK)
        { 
            fprintf(stderr, "[CLIENT] error: CLIENT sended EOF, but failed to send it to remote SERVER\n");
        }
        printf("[CLIENT] > Sending EOF to remote SERVER\n");
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel sended EOF, but [client-session] channel is closed\n");        
    }

}

static void channel_exit_status(ssh_session session, ssh_channel channel, int exit_status, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;    
    (void) session;
    (void) channel;
    int rc;

    // printf("[CALLBACK] channel_exit_status\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_request_send_exit_status(sdata->client_channel, exit_status);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[CLIENT] error: CLIENT sended exit_status:%d, but failed to send it to remote SERVER\n", exit_status);
        }
        printf("[CLIENT] > Exit status %d", exit_status);
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel sended Exit status %d, but [client-session] channel is closed\n", exit_status);                
    }
}

static void channel_exit_signal(ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg, const char *lang, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    (void) channel;
    int rc;

    // printf("[CALLBACK] channel_exit_siganl\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_request_send_exit_signal(sdata->client_channel, signal, core, errmsg, lang);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[CLIENT] error: CLIENT sended exit_signal:%s core=%d errmsg=%s lang=%s, but failed to send it to remote SERVER\n", signal, core, errmsg, lang);
        }
        printf("[CLIENT] > Exit signal:%s core=%d errmsg=%s lang=%s", signal, core, errmsg, lang);
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel sended Exit signal %s, but [client-session] channel is closed\n", signal);            
    }
}


static void channel_close_function(ssh_session session, ssh_channel channel, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    (void) channel;
    int rc;

    // printf("[CALLBACK] channel_close\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_close(sdata->client_channel);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[CLIENT] error: CLIENT closed channel %d, but failed to close remote SERVER channel\n", sdata->chan_id);
        }
        printf("[CLIENT] > Closing remote channel %d\n", sdata->chan_id);
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel closed, but [client-session] channel is already closed\n", signal);            
    }
}

static void channel_signal(ssh_session session, ssh_channel channel, const char *signal, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    (void) channel;
    int rc;

    // printf("[CALLBACK] channel_signal\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_request_send_signal(sdata->client_channel, signal);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[CLIENT] error: Client sended signal %s, but failed to send it to remote SERVER\n", signal);
        }
        printf("[CLIENT] > Sending signal = %s\n", signal);
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel sended signal = %s, but [client-session] channel is closed\n", signal);            
    }
}

static int channel_env_request(ssh_session session, ssh_channel channel, const char *env_name, const char *env_value, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    (void) channel;
    int rc;

    // printf("[CALLBACK] channel_env_request\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_request_env(sdata->client_channel, env_name, env_value);
        printf("[CLIENT] > Sending environment\n");
        printf("[CLIENT] > Sending env %s = %s\n", env_name, env_value);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[CLIENT] error: Client send env %s = %s, but failed to send it to remote SERVER\n", env_name, env_value);
            return 1;
        }
        printf("[CLIENT] channel %d: request env confirm 0\n", sdata->chan_id);
        return 0;
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel sended env %s = %s, but [client-session] channel is closed\n", env_name, env_value);            
    }
}

static int channel_pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    (void) channel;
    (void) py;
    (void) px;
    int rc;

    // printf("[CALLBACK] channel_pty_request\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_request_pty_size(sdata->client_channel, term, cols, rows);
        printf("[CLIENT] > Request %s cols = %d rows = %d\n", term, cols, rows);
        if (rc != SSH_OK)
        {
            fprintf(stderr, "[CLIENT] error: Failed to request pty\n");
            return -1;
        }
        printf("[CLIENT] channel %d: open confirm rwindow 32000 rmax 35000\n", sdata->chan_id);
        printf("[CLIENT] PTY allocation request accepted on channel %d\n", sdata->chan_id);
        return 0;
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel request %s cols = %d rows = %d, but [client-session] channel is closed\n", term, cols, rows);       
    }
}

static int channel_pty_window_change(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    (void) channel;
    (void) py;
    (void) px;
    int rc;

    // printf("[CALLBACK] channel_pty_window_change\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_change_pty_size(sdata->client_channel, cols, rows);
        printf("[CLIENT] > Changing pty size cols = %d rows = %d\n", cols, rows);
        if (rc != SSH_OK)
        {
            fprintf(stderr, "[CLIENT] error: Failed to change pty size\n");
            return -1;
        }   
        printf("[CLIENT] channel %d: request window-change confirm 0\n", sdata->chan_id);
        return 0;
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel request change pty size %s cols = %d rows = %d, but [client-session] channel is closed\n", cols, rows);       
    }
}

static int channel_shell_request(ssh_session session, ssh_channel channel, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata; 
    (void) session;
    (void) channel;
    int rc;

    // printf("[CALLBACK] channel_shell_request\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_request_shell(sdata->client_channel);
        if (rc != SSH_OK)
        {
            fprintf(stderr, "[CLIENT] error: Failed to request shell\n");
            return 1;
        }
        printf("[CLIENT] channel %d: request shell confirm 1\n", sdata->chan_id);
        sdata->shell = 1;
        return 0;
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel request shell, but [client-session] channel is closed\n");          
    }
}
static int channel_exec_request(ssh_session session, ssh_channel channel, const char *command, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata; 
    (void) session;
    (void) channel;
    int rc;

    // printf("[CALLBACK] channel_exec_request\n");
    if(ssh_channel_is_open(sdata->client_channel))
    {
        rc = ssh_channel_request_exec(sdata->client_channel, command);
        printf("[CLIENT] ==> Exec command %s\n", command);
        if (rc != SSH_OK)
        {
            return 1;
        }
        return 0;
    }
    else
    {
        fprintf(stderr, "[CLIENT] error: [server-session] channel execute command: %s, but [client-session] channel is closed\n", command);          
    }
}

static int channel_subsystem_request(ssh_session session, ssh_channel channel, const char *subsystem, void *userdata)
{
    // printf("[CALLBACK] channel_subsystem_request\n");
}

static void global_request_function(ssh_session session, ssh_message message, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    int message_type;
    int message_subtype;
    
    // printf("[CALLBACK] global_request_function\n");

    message_type = ssh_message_type(message);
    message_subtype = ssh_message_subtype(message);
    printf("[CLIENT]  message type:%d subtype:%d\n", message_type, message_subtype);
}

static int forward_stdin(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    (void) session;
    (void) channel;
    (void) is_stderr;
    int nbytes;

    // printf("[CALLBACK] channel_data\n");
    if (ssh_channel_is_closed(sdata->client_channel) || len <= 0)
    {
        return 0;
    }

    nbytes = ssh_channel_write(sdata->client_channel, (char *) data, len);
    if(nbytes > 0)
    {
        // printf("%s", data);
        printf("[SERVER] <== SEND %d bytes stdin data\n", nbytes);
        // printf(" ==> Recv %u bytes, Write %d bytes into child_stdin\n", len, nbytes);
    }
    return nbytes;
}

static void* client_handler(void *userdata)
{
    struct session_data_struct *sdata = (struct session_data_struct *) userdata;
    struct ssh_callbacks_struct client_cb = {
        .userdata = &sdata,
        .global_request_function = global_request_function,
        // .channel_open_request_x11_function = channel_open_request_x11_function,
        // .channel_open_request_auth_agent_function,
        // .auth_function = auth_function,
        // .log_function = log_function,
        // ABANDONED FUNCTION
        // .connect_status_function = connect_status_function,
    };
    int rc;
    char buf[BUF_SIZE];
    int nbytes = -1;

    pthread_detach(pthread_self());

    ssh_init();
    if(ssh_init() == -1)
    {
        fprintf(stderr, "[CLIENT] error: Failed initializing ssh client: ssh_init() failed\n");
    }

    sdata->client_session = connect_ssh(sdata->rhost, NULL, sdata->rport ,0);

    if(sdata->client_session == NULL)
    {
        fprintf(stderr,"[CLIENT] error: Connecting SERVER failed : %s\n",ssh_get_error(sdata->client_session));
        ssh_finalize();
    }
    printf("[CLIENT] Connecting SERVER %s\n", REMOTE_HOST);

    ssh_callbacks_init(&client_cb);
    ssh_set_callbacks(sdata->client_session, &client_cb);
    sdata->client_event = ssh_event_new();
    ssh_event_add_session(sdata->client_event, sdata->client_session);

    printf("[CLIENT] * Wait for client shell\n");
    while(sdata->shell != 1);

    printf("[*** CLIENT EVENT LOOP ***]\n");
    while (ssh_channel_is_open(sdata->client_channel))
    {
        nbytes = ssh_channel_read(sdata->client_channel, buf, sizeof(buf), 0);
        while(nbytes > 0)
        {
            ssh_channel_write(sdata->server_channel, buf, nbytes);
            printf("[CLIENT] ==> RECV %d stdout data\n", nbytes);
            nbytes = ssh_channel_read(sdata->client_channel, buf, sizeof(buf), 0);
        }
        nbytes = ssh_channel_read(sdata->client_channel, buf, sizeof(buf), 1);
        while(nbytes > 0)
        {
            ssh_channel_write_stderr(sdata->server_channel, buf, nbytes);
            printf("[CLIENT] ==> RECV %d stderr data\n", nbytes);
            nbytes = ssh_channel_read(sdata->client_channel, buf, sizeof(buf), 1);            
        }
        continue;
    }
    printf("[*** CLIENT EVENT LOOP END ***]\n");

    // printf("[PTHREAD] ID：0x%d exit\n", pthread_self());
    // pthread_exit(0);
}

static void server_handler(ssh_event event, ssh_session session, struct arguments *args) 
{
    int n;
    int rc = 0;

    /* Our struct holding information about the session. */
    struct session_data_struct sdata = {
        .rhost = 0,
        .rport = 0,
        .tid = 0,
        .client_session = NULL,
        .server_channel = NULL,
        .client_channel = NULL,
        .chan_id = -1,
        .auth_attempts = 0,
        .authenticated = 0,
        .server_event = NULL,
        .client_event = NULL,
        .shell = 0,
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &sdata,
        .channel_pty_request_function = channel_pty_request,
        .channel_pty_window_change_function = channel_pty_window_change,
        .channel_shell_request_function = channel_shell_request,
        .channel_exec_request_function = channel_exec_request,
        .channel_data_function = forward_stdin,
        .channel_subsystem_request_function = channel_subsystem_request,
        
        .channel_eof_function = channel_eof,
        .channel_close_function = channel_close_function,
        .channel_signal_function = channel_signal,
        .channel_env_request_function = channel_env_request,
        .channel_exit_status_function = channel_exit_status,
        .channel_exit_signal_function = channel_exit_signal,
        // .channel_auth_agent_req_function = channel_auth_agent_req,
        // .channel_x11_req_function = channel_x11_req,
        // .channel_write_wontblock_function = channel_write_wontblock,
    };

    struct ssh_server_callbacks_struct server_cb = {
        .userdata = &sdata,
        .auth_none_function = auth_none,
        // .auth_pubkey_function = auth_pubkey,
        // .auth_gssapi_mic_function = auth_gssapi_mic,
        .auth_password_function = auth_password,
        // .service_request_function = service_request,
        .channel_open_request_session_function = channel_open_request_session,
        // ABANDONED FUNCTION
        // .gssapi_select_oid_function = gssapi_select_oid_function,
        // .gssapi_accept_sec_ctx_function = gssapi_accept_sec_ctx_function,
        // .gssapi_verify_mic_function = gssapi_verify_mic_function,
    };


    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
    printf("[SERVER] Set auth methods: (password)\n");
    
    ssh_callbacks_init(&server_cb);
    ssh_callbacks_init(&channel_cb);
    
    ssh_set_server_callbacks(session, &server_cb);
    // printf(" Set server side session callback\n");

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "[SERVER] error: Handler key exchange error: %s\n", ssh_get_error(session));
        return;
    }
    // printf(" Server side handle key exchange\n");

    ssh_event_add_session(event, session);
    // printf(" Add server side session to event\n");

/////////////////////////////////////////////////////////////////////////////////////

    sdata.rhost = args->rhost;
    sdata.rport = args->rport;
    printf("[CLIENT] * Wait for connecting remote SERVER\n");
    if(pthread_create(&sdata.tid, NULL, client_handler, (void *)&sdata) != 0)
    {
        fprintf(stderr, "[PTHREAD] error: Failed to create client thread\n");
        return;
    }
    while(sdata.client_session == NULL)
    {
        continue;
    }

/////////////////////////////////////////////////////////////////////////////////////

    n = 0;
    printf("[SERVER] * If the user has used up all attempts, or if he hasn't been able to authenticate in 60 seconds (n * 100ms), disconnect\n");  
    while (sdata.authenticated == 0 || sdata.server_channel == NULL) {
        /* If the user has used up all attempts, or if he hasn't been able to
         * authenticate in 60 seconds (n * 100ms), disconnect. */       
        if (sdata.auth_attempts >= 3 || n >= 600) {
            return;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "[SERVER] error: SSH_ERROR %s\n", ssh_get_error(session));
            return;
        }
        n++;
    }

    ssh_set_channel_callbacks(sdata.server_channel, &channel_cb);
    // printf("[SERVER] Set server side channel callbacks\n");

    printf("[*** SERVER EVENT LOOP ***]\n");

    while(ssh_channel_is_open(sdata.server_channel) && ssh_channel_is_open(sdata.client_channel))
    {
        /* Poll the main event which takes care of the session, the channel and
         * even our child process's stdout/stderr (once it's started). */
        if ((ssh_event_dopoll(event, -1) == SSH_ERROR))
        {
            fprintf(stderr, "[SERVER] error: %s\n", ssh_get_error(session));
            ssh_channel_close(sdata.server_channel);
        }
    };

    printf("[*** SERVER EVENT LOOP END ***]\n");
    ssh_channel_send_eof(sdata.server_channel);
    if(ssh_channel_is_open(sdata.server_channel))
    {  
        ssh_channel_close(sdata.server_channel);
    }

    printf("[SERVER] logout\n");
    /* Wait up to 5 seconds for the client to terminate the session. */
    printf("[SERVER] * Wait up to 5 seconds for the client to terminate the session\n");
    for (n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) 
    {
        ssh_event_dopoll(event, 100);
    }

    ssh_event_free(sdata.client_event);
    ssh_channel_free(sdata.client_channel);
    ssh_disconnect(sdata.client_session);
    ssh_free(sdata.client_session);

    ssh_channel_free(sdata.server_channel);
}

/* SIGCHLD handler for cleaning up dead children. */
static void sigchld_handler(int signo) {
    (void) signo;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char **argv) 
{
    ssh_bind sshbind;
    ssh_session session;
    ssh_event event;

    int port = 2222;
    int verbosity = 0;

    struct sigaction sa;
    int rc;

// #ifdef HAVE_ARGP_H
    struct arguments args = {
        .hostkey = NULL,
        .rsakey = NULL, 
        .dsakey = NULL, 
        .ecdsakey = NULL,
        .rhost = NULL,
        .rport = 0,
        .lport = 0,
    };

    argp_parse(&argp, argc, argv, 0, 0, &args);

// #endif /* HAVE_ARGP_H */

    /* Set up SIGCHLD handler. */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        fprintf(stderr, "[SERVER] error: Failed to register SIGCHLD handler\n");
        return 1;
    }
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    // printf(" Set client thread callback\n");

    rc = ssh_init();
    if (rc < 0) {
        fprintf(stderr, "[SERVER] error: ssh_init failed\n");
        return 1;
    }

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "[SERVER] error: ssh_bind_new failed\n");
        return 1;
    }

    printf("rsakey : %s\n", args.rsakey);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &args.lport);   
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, &args.verbosity);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, args.rsakey);
    // ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, args.dsakey);
    // ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, args.ecdsakey);
    // ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, args.hostkey);
        
    printf("[SERVER] Listening on local port %d\n", args.lport);

    if(ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "[SERVER] error: Error on sshbind %s\n", ssh_get_error(sshbind));
        return 1;
    }

    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "[SERVER] error: Failed to allocate session\n");
            continue;
        }

        /* Blocks until there is a new incoming connection. */
        if(ssh_bind_accept(sshbind, session) != SSH_ERROR) {
            printf("[SERVER] Bind accept\n");
            switch(fork()) {
                case 0:
                    /* Remove the SIGCHLD handler inherited from parent. */
                    sa.sa_handler = SIG_DFL;
                    sigaction(SIGCHLD, &sa, NULL);
                    /* Remove socket binding, which allows us to restart the
                     * parent process, without terminating existing sessions. */
                    ssh_bind_free(sshbind);

                    event = ssh_event_new();
                    if (event != NULL) {
                        /* Blocks until the SSH session ends by either
                         * child process exiting, or client disconnecting. */
                        server_handler(event, session, &args);
                        ssh_event_free(event);
                      
                        // printf("==> *Blocks until the SSH session ends by either child process exiting, or client disconnecting\n");
                    } else {
                        fprintf(stderr, "[SERVER] error: Could not create polling context\n");
                    }
                    ssh_disconnect(session);
                    ssh_free(session);

                    exit(0);
                case -1:
                    fprintf(stderr, "[SERVER] error: Failed to fork\n");
            }
        } else {
            fprintf(stderr, "[SERVER] error: Error on sshbind %s\n", ssh_get_error(sshbind));
        }
        /* Since the session has been passed to a child fork, do some cleaning
         * up at the parent process. */
        ssh_disconnect(session);
        ssh_free(session);
        // printf("==> *Since the session has been passed to a child fork, do some cleaning up at the parent process\n");
    }

    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}