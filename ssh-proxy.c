#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/time.h>
// #include <sys/stat.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARGP_H
#include <argp.h>
#endif
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif

#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include<pthread.h>
#include <poll.h>

#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <libssh/libssh.h>

#include "common.h"

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

#define BUF_SIZE 1048576
#define SESSION_END (SSH_CLOSED | SSH_CLOSED_ERROR)
#define SFTP_SERVER_PATH "/usr/lib/sftp-server"

#define REMOTE_HOST "10.100.1.33"
#define REMOTE_PORT 22

static struct termios terminal;

#ifndef HAVE_CFMAKERAW
static void cfmakeraw(struct termios *termios_p)
{
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
}
#endif

static void do_cleanup(int i)
{
    /* unused variable */
    (void) i;

    tcsetattr(0, TCSANOW, &terminal);
}




static int auth_none(ssh_session session, const char *user, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;

    int rc;
    char *banner;

    printf("[CALLBACK] auth_none\n");

    if(sess_data->client_session != NULL)
    {
        rc = ssh_userauth_none(sess_data->client_session, user);

        if (rc == SSH_AUTH_SUCCESS)
        {
            sess_data->authenticated = 1;
            printf("[+] Authentication successed (none), user:%s\n", user);
            return rc;
        }
    }
    else
    {
        fprintf(stderr, "[-] Client session is NULL\n");
    }

    banner = ssh_get_issue_banner(sess_data->client_session);
    if(banner)
    {
        printf("%s\n", banner);
        free(banner);
    }

    return rc;
}

static int auth_password(ssh_session session, const char *user, const char *pass, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;

    int rc;

    printf("[CALLBACK] auth_password\n");

    rc = ssh_userauth_password(sess_data->client_session, user, pass);
    printf("[+] ==> Try auth with Username:%s and Password:%s\n", user, pass);

    if (rc == SSH_AUTH_SUCCESS)
    {
        sess_data->authenticated = 1;
        printf("[+] Authentication successed (password), user:%s\n", user);
        return SSH_AUTH_SUCCESS;
    }

    sess_data->auth_attempts++;
    printf("[*] *Have tried %d auth\n", sess_data->auth_attempts);
    return SSH_AUTH_DENIED;
}

static ssh_channel channel_open_request_session(ssh_session session, void *userdata) 
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    int rc;    

    printf("[CALLBACK] channel_open_request_session\n");

    sess_data->chan_id++;

    sess_data->server_channel = ssh_channel_new(session);
    printf("[+] <== channel %d: new [server-session]\n", sess_data->chan_id);

    sess_data->client_channel = ssh_channel_new(sess_data->client_session);
    if(sess_data->client_channel == NULL)
    {
        fprintf(stderr,"[-] Open session failed : %s\n",ssh_get_error(sess_data->client_channel));
        ssh_channel_free(sess_data->client_channel);
        return NULL;
    }

    printf("[+] ==> channel %d: new [client-session]\n", sess_data->chan_id);

    rc = ssh_channel_open_session(sess_data->client_channel);
    printf("[+] ==> channel %d: send open\n", sess_data->chan_id);
    if(rc != SSH_OK)
    {
        fprintf(stderr,"[-] Open session failed : %s\n",ssh_get_error(sess_data->client_channel));
        ssh_channel_free(sess_data->client_channel);
        return NULL;
    }

    return sess_data->server_channel;
}

static void channel_eof(ssh_session session, ssh_channel channel, void *userdata)
{    
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) channel;

    int rc;
    
    printf("[CALLBACK] channel_eof\n");

    if(ssh_channel_is_open(sess_data->client_channel))
    {
        rc = ssh_channel_send_eof(sess_data->client_channel);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[-] CLIENT sended EOF, but failed to send it to SERVER\n");
        }
        printf("[+] ==> Sending EOF to remote channel\n");
    }
    else
    {
        fprintf(stderr, "[-] CLIENT sended EOF, but SERVER channel is closed\n");
    }
}

static void channel_exit_status(ssh_session session, ssh_channel channel, int exit_status, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata; 
    
    (void) session;
    (void) channel;

    int rc;

    printf("[CALLBACK] channel_exit_status\n");

    if(ssh_channel_is_open(sess_data->client_channel))
    {
        rc = ssh_channel_request_send_exit_status(sess_data->client_channel, exit_status);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[-] CLIENT sended exit_status:%d, but failed to send it to SERVER\n", exit_status);
        }
        printf("[+] ==> Exit status %d", exit_status);
    }
    else
    {
        fprintf(stderr, "[-] CLIENT sended exit_status:%d, but SERVER channel is closed\n", exit_status);
    }
}

static void channel_exit_signal(ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg, const char *lang, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;
    (void) channel;

    int rc;

    printf("[CALLBACK] channel_exit_siganl\n");

    if(ssh_channel_is_open(sess_data->client_channel))
    {
        rc = ssh_channel_request_send_exit_signal(sess_data->client_channel, signal, core, errmsg, lang);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[-] CLIENT sended exit_signal:%s core=%d errmsg=%s lang=%s, but failed to send it to SERVER\n", signal, core, errmsg, lang);
        }
        printf("[+] ==> Sending exit_signal:%s core=%d errmsg=%s lang=%s", signal, core, errmsg, lang);
    }
    else
    {
        fprintf(stderr, "[-] CLIENT sended exit_signal:%s core=%d errmsg=%s lang=%s, but SERVER channel is closed\n", signal, core, errmsg, lang);
    }
}


static void channel_close_function(ssh_session session, ssh_channel channel, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;
    (void) channel;

    int rc;

    printf("[CALLBACK] channel_close\n");

    if(ssh_channel_is_open(sess_data->client_channel))
    {
        rc = ssh_channel_close(sess_data->client_channel);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[-] CLIENT closed channel %d, but failed to close SERVER channel\n", sess_data->chan_id);
        }
        printf("[+] ==> Closing remote channel %d\n", sess_data->chan_id);
    }
    else
    {
        fprintf(stderr, "[-] CLIENT closed channel %d, but SERVER channel is already closed\n", sess_data->chan_id);
    }
}

static void channel_signal(ssh_session session, ssh_channel channel, const char *signal, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;
    (void) channel;

    int rc;

    printf("[CALLBACK] channel_signal\n");
;
    if(ssh_channel_is_open(sess_data->client_channel))
    {
        rc = ssh_channel_request_send_signal(sess_data->client_channel, signal);
        if(rc != SSH_OK)
        {
            fprintf(stderr, "[-] Client sended signal %s, but failed to send it to SERVER\n", signal);
        }
        printf("[+] ==> Sending signal = %s\n", signal);
    }
    else
    {
        fprintf(stderr, "[-] Client sended signal %s, but SERVER channel is closed\n", signal);
    }
}
static int channel_env_request(ssh_session session, ssh_channel channel, const char *env_name, const char *env_value, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;
    (void) channel;

    int rc;

    printf("[CALLBACK] channel_env_request\n");

    if(ssh_channel_is_closed(sess_data->client_channel))
    {
        fprintf(stderr, "[-] Client send env %s = %s, but SERVER channel is closed\n", env_name, env_value);
        return 1;
    }

    rc = ssh_channel_request_env(sess_data->client_channel, env_name, env_value);
    printf("[+] ==> Sending environment\n");
    printf("[+] ==> Sending env %s = %s\n", env_name, env_value);
    if(rc != SSH_OK)
    {
        fprintf(stderr, "[-] Client send env %s = %s, but failed to send it to SERVER\n", env_name, env_value);
        return 1;
    }
    printf("[+] channel %d: request env confirm 0\n", sess_data->chan_id);
    return 0;

}

static int channel_data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;
    (void) channel;
    (void) is_stderr;

    int nbytes;

    // printf("[CALLBACK] channel_data\n");

    if (ssh_channel_is_closed(sess_data->client_channel) || len <= 0)
    {
        return 0;
    }

    nbytes = write(sess_data->child_stdin, (char *) data, len);
    if(nbytes != 0)
    printf("[+] ==> Recv %len bytes, Write %d bytes into child_stdin\n", len, nbytes);
    return nbytes;
}

static int channel_pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;
    (void) channel;
    (void) py;
    (void) px;
    
    int rc;

    printf("[CALLBACK] channel_pty_request\n");

    rc = ssh_channel_request_pty_size(sess_data->client_channel, term, cols, rows);
    printf("[+] ==> Request %s cols = %d rows = %d\n", term, cols, rows);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "[-] Failed to request pty\n");
        return -1;
    }
    printf("[+] channel %d: open confirm rwindow\n", sess_data->chan_id);
    printf("[+] PTY allocation request accepted on channel %d\n", sess_data->chan_id);
    return 0;
}

static int channel_pty_window_change(ssh_session session, ssh_channel channel, int cols, int rows, int py, int px, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;

    (void) session;
    (void) channel;
    (void) py;
    (void) px;
    
    int rc;

    printf("[CALLBACK] channel_pty_window_change\n");
    
    rc = ssh_channel_change_pty_size(sess_data->client_channel, cols, rows);
    printf("[+] ==> Changing pty size cols = %d rows = %d\n", cols, rows);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "[-] Failed to change pty size\n");
        return -1;
    }   
    printf("[+] channel %d: request window-change confirm 0\n", sess_data->chan_id);
    return 0;
}

static int channel_shell_request(ssh_session session, ssh_channel channel, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;
    
    (void) session;
    (void) channel;
    
    int rc;
    int buf;
    int nbytes;

    printf("[CALLBACK] channel_shell_request\n");

    rc = ssh_channel_request_shell(sess_data->client_channel);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "[-] Failed to request shell\n");
        return 1;
    }

    printf("[+] ==> Entering interactive session\n");
    printf("[+] ==> channel %d: request shell confirm 1\n", sess_data->chan_id);

    sess_data->shell = 1;

    return 0;
}
static int channel_exec_request(ssh_session session, ssh_channel channel, const char *command, void *userdata)
{
    printf("[CALLBACK] channel_exec_request\n");
}

static int channel_subsystem_request(ssh_session session, ssh_channel channel, const char *subsystem, void *userdata)
{
    printf("[CALLBACK] channel_subsystem_request\n");
}


static void global_request_function(ssh_session session, ssh_message message, void *userdata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) userdata;
    int message_type;
    int message_subtype;
    
    printf("[CALLBACK] global_request_function\n");

    message_type = ssh_message_type(message);
    message_subtype = ssh_message_subtype(message);
    printf("message type:%d subtype:%d\n");
}

static int process_stdin(socket_t fd, int revents, void *userdata)
{
    printf("[CALLBACK] process_stdin\n");
    char buf[BUF_SIZE];
    int nbytes = -1;
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0)
    {
        nbytes = read(fd, buf, BUF_SIZE);
        if (nbytes > 0)
        {
            ssh_channel_write(channel, buf, nbytes);
            n = write(1, buf, nbytes);
        }
    }

    return nbytes;
}

static int process_stdout(socket_t fd, int revents, void *userdata) 
{
    printf("[CALLBACK] process_stdout\n");
    char buf[BUF_SIZE];
    int nbytes = -1;
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) 
    {
        nbytes = read(fd, buf, BUF_SIZE);
        if (nbytes > 0) 
        {
            ssh_channel_write(channel, buf, nbytes);
            n = write(1, buf, nbytes);
        }
    }

    return nbytes;
}

static int process_stderr(socket_t fd, int revents, void *userdata) 
{
    printf("[CALLBACK] process_stderr\n");
    char buf[BUF_SIZE];
    int nbytes = -1;
    int n = -1;
    ssh_channel channel = (ssh_channel) userdata;

    if (channel != NULL && (revents & POLLIN) != 0) 
    {
        nbytes = read(fd, buf, BUF_SIZE);
        if (nbytes > 0) 
        {
            ssh_channel_write_stderr(channel, buf, nbytes);
            n = write(1, buf, nbytes);
        }
    }

    return nbytes;
}


static void* client_handler(void *sessiondata)
{
    struct session_data_struct *sess_data = (struct session_data_struct *) sessiondata;
    struct termios terminal_local;
    struct ssh_callbacks_struct client_cb = {
        .userdata = &sess_data,
        .global_request_function = global_request_function,
        // .channel_open_request_x11_function = channel_open_request_x11_function,
        // .channel_open_request_auth_agent_function,
        // .auth_function = auth_function,
        // .log_function = log_function,
        // ABANDONED FUNCTION
        // .connect_status_function = connect_status_function,
    };

    int interactive = isatty(0);

    ssh_connector connector_in, connector_out, connector_err;

    ssh_init();
    if(ssh_init() == -1)
    {
        fprintf(stderr, "Failed initializing ssh client: ssh_init() failed\n");
    }

    sess_data->client_session = connect_ssh(REMOTE_HOST, NULL, 0);

    if(sess_data->client_session == NULL)
    {
        fprintf(stderr,"[-] Connecting SERVER failed : %s\n",ssh_get_error(sess_data->client_session));
        ssh_finalize();
    }
    printf("[+] Connecting SERVER %s\n", REMOTE_HOST);

    ssh_callbacks_init(&client_cb);
    ssh_set_callbacks(sess_data->client_session, &client_cb);
    sess_data->client_event = ssh_event_new();
    // ssh_event_add_session(sess_data->client_event, sess_data->client_session);
    
    /* stdin */
    connector_in = ssh_connector_new(sess_data->client_session);
    ssh_connector_set_in_fd(connector_in, 0);
    ssh_connector_set_out_channel(connector_in, sess_data->client_channel, SSH_CONNECTOR_STDINOUT);
    ssh_event_add_connector(sess_data->client_event, connector_in);

    /* stdout */
    connector_out = ssh_connector_new(sess_data->client_session);
    ssh_connector_set_out_fd(connector_out, 1);
    ssh_connector_set_in_channel(connector_out, sess_data->client_channel, SSH_CONNECTOR_STDINOUT);
    ssh_event_add_connector(sess_data->client_event, connector_out);

    /* stderr */
    connector_err = ssh_connector_new(sess_data->client_session);
    ssh_connector_set_out_fd(connector_err, 2);
    ssh_connector_set_in_channel(connector_err, sess_data->client_channel, SSH_CONNECTOR_STDERR);
    ssh_event_add_connector(sess_data->client_event, connector_err);


    while(ssh_channel_is_closed(sess_data->client_channel))
    {
        continue;
    }
    
    if(interactive)
    {
        tcgetattr(0, &terminal_local);
        memcpy(&terminal, &terminal_local, sizeof(struct termios));
    }

    while (sess_data->shell != 1)
    {
        continue;
    }

    if(interactive)
    {
        cfmakeraw(&terminal_local);
        tcsetattr(0, TCSANOW, &terminal_local);
    }
    signal(SIGTERM, do_cleanup);

    printf("[*** CLIENT EVENT LOOP ***]\n");
    while (ssh_channel_is_open(sess_data->client_channel))
    {
        // if(ssh_event_dopoll(sess_data->client_event, -1) == SSH_ERROR)
        // {
        //     fprintf(stderr, "[-] SSH_ERROR %s\n", ssh_get_error(sess_data->client_session));
        //     break;
        // } 
        continue;
    }
    
    printf("[*** CLIENT EVENT LOOP END ***]\n");

    // close(sess_data->child_stdin);
    /* Remove the descriptors from the polling context, since they are now
     * closed, they will always trigger during the poll calls. */

    ssh_event_remove_connector(sess_data->client_event, connector_in);
    ssh_event_remove_connector(sess_data->client_event, connector_out);
    ssh_event_remove_connector(sess_data->client_event, connector_err);

    ssh_connector_free(connector_in);
    ssh_connector_free(connector_out);
    ssh_connector_free(connector_err);

    ssh_event_free(sess_data->client_event);    

    if (interactive)
    {
        do_cleanup(0);
    }

    ssh_channel_free(sess_data->client_channel);

    ssh_disconnect(sess_data->client_session);
    ssh_free(sess_data->client_session);
}

static void server_handler(ssh_event event, ssh_session session) 
{
    int n;
    int rc;
    pthread_t tid;

    /* Our struct holding information about the session. */
    struct session_data_struct sess_data = {
        // .client_session = NULL,
        // // .client_channel = NULL,
        .client_session = NULL,
        .server_channel = NULL,
        .client_channel = NULL,
        .chan_id = -1,
        .auth_attempts = 0,
        .authenticated = 0,
        .server_event = NULL,
        .client_event = NULL,
        .child_stdin = -1,
        .child_stdout = -1,
        .child_stderr = -1,
        .shell = 0,
    };

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = &sess_data,
        .channel_pty_request_function = channel_pty_request,
        .channel_pty_window_change_function = channel_pty_window_change,
        .channel_shell_request_function = channel_shell_request,
        .channel_exec_request_function = channel_exec_request,
        .channel_data_function = channel_data_function,
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
        .userdata = &sess_data,
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
    printf("[+] ==> Set auth methods: (password)\n");
    
    ssh_callbacks_init(&server_cb);
    ssh_callbacks_init(&channel_cb);
    
    ssh_set_server_callbacks(session, &server_cb);
    // printf("[+] Set server side session callback\n");

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "%s\n", ssh_get_error(session));
        return;
    }
    // printf("[+] Server side handle key exchange\n");
    
    ssh_event_add_session(event, session);
    // printf("[+] Add server side session to event\n");

/////////////////////////////////////////////////////////////////////////////////////
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    printf("[+] Set client thread callback\n");
    if(pthread_create(&tid, NULL, client_handler, (void *)&sess_data) != 0)
    {
        fprintf(stderr, "[-] Failed to create client thread\n");
        return;
    }
    // printf("[+] Create client thread\n");
    printf("[+] Wait for connecting SERVER\n");
    
    while(sess_data.client_session == NULL)
    {
        continue;
    }

/////////////////////////////////////////////////////////////////////////////////////

    n = 0;
    printf("[*] *If the user has used up all attempts, or if he hasn't been able to authenticate in 60 seconds (n * 100ms), disconnect\n");  
    while (sess_data.authenticated == 0 || sess_data.server_channel == NULL) {
        /* If the user has used up all attempts, or if he hasn't been able to
         * authenticate in 60 seconds (n * 100ms), disconnect. */       
        if (sess_data.auth_attempts >= 3 || n >= 600) {
            return;
        }

        if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
            fprintf(stderr, "[-] %s\n", ssh_get_error(session));
            return;
        }
        n++;
    }

    if(sess_data.server_channel == NULL)
    {
        fprintf(stderr, "[-] Channel is NULL\n");
        return;
    }
    ssh_set_channel_callbacks(sess_data.server_channel, &channel_cb);
    printf("[+] Set server side channel callbacks\n");

    printf("[*** SERVER EVENT LOOP ***]\n");
    do 
    {
        /* Poll the main event which takes care of the session, the channel and
         * even our child process's stdout/stderr (once it's started). */
        if (ssh_event_dopoll(event, -1) == SSH_ERROR) 
        {
            fprintf(stderr, "[-] %s\n", ssh_get_error(session));
            ssh_channel_close(sess_data.server_channel);
        }

        /* If child process's stdout/stderr has been registered with the event,
         * or the child process hasn't started yet, continue. */
        if (sess_data.server_event != NULL)
        {
            continue;
        }
        /* Executed only once, once the child process starts. */
        sess_data.server_event = event;
        /* If stdout valid, add stdout to be monitored by the poll event. */
        if (sess_data.child_stdout != -1) 
        {
            if (ssh_event_add_fd(event, sess_data.child_stdout, POLLIN, process_stdout, sess_data.server_channel) != SSH_OK) 
            {
                fprintf(stderr, "[-] Failed to register stdout to poll context\n");
                ssh_channel_close(sess_data.server_channel);
            }
        }
        printf("[+] Register stdout to poll context\n");
        /* If stderr valid, add stderr to be monitored by the poll event. */
        if (sess_data.child_stderr != -1)
        {
            if (ssh_event_add_fd(event, sess_data.child_stderr, POLLIN, process_stderr, sess_data.server_channel) != SSH_OK) 
            {
                fprintf(stderr, "Failed to register stderr to poll context\n");
                ssh_channel_close(sess_data.server_channel);
            }
        }
        printf("[+] Register stderr to poll context\n");
    } while(ssh_channel_is_open(sess_data.server_channel));
 
    close(sess_data.child_stdout);
    close(sess_data.child_stderr);

    /* Remove the descriptors from the polling context, since they are now
     * closed, they will always trigger during the poll calls. */
    ssh_event_remove_fd(event, sess_data.child_stdout);
    ssh_event_remove_fd(event, sess_data.child_stderr);

    printf("[*** SERVER EVENT LOOP END ***]\n");
    ssh_channel_send_eof(sess_data.server_channel);
    ssh_channel_close(sess_data.server_channel);

    /* Wait up to 5 seconds for the client to terminate the session. */
    printf("[*] *Wait up to 5 seconds for the client to terminate the session\n");
    for (n = 0; n < 50 && (ssh_get_status(session) & SESSION_END) == 0; n++) 
    {
        ssh_event_dopoll(event, 100);
    }
}

/* SIGCHLD handler for cleaning up dead children. */
static void sigchld_handler(int signo) {
    (void) signo;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char** argv) {

    ssh_bind sshbind;
    ssh_session session;
    ssh_event event;

    int port = 2222;
    int verbosity = 0;

    struct sigaction sa;
    int rc;

    /* Set up SIGCHLD handler. */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) != 0) {
        fprintf(stderr, "[-] Failed to register SIGCHLD handler\n");
        return 1;
    }

    rc = ssh_init();
    if (rc < 0) {
        fprintf(stderr, "[-] ssh_init failed\n");
        return 1;
    }

    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "[-] ssh_bind_new failed\n");
        return 1;
    }

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");    
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, &verbosity);    

    printf("[+] Listening on local port %d\n", port);

    if(ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "[-] %s\n", ssh_get_error(sshbind));
        return 1;
    }

    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "[-] Failed to allocate session\n");
            continue;
        }

        /* Blocks until there is a new incoming connection. */
        if(ssh_bind_accept(sshbind, session) != SSH_ERROR) {
            printf("[+] Bind accept\n");
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
                        server_handler(event, session);
                        ssh_event_free(event);
                        printf("[*] *Blocks until the SSH session ends by either child process exiting, or client disconnecting\n");
                    } else {
                        fprintf(stderr, "[-] Could not create polling context\n");
                    }
                    ssh_disconnect(session);
                    ssh_free(session);


                    exit(0);
                case -1:
                    fprintf(stderr, "[-] Failed to fork\n");
            }
        } else {
            fprintf(stderr, "[-] %s\n", ssh_get_error(sshbind));
        }
        /* Since the session has been passed to a child fork, do some cleaning
         * up at the parent process. */
        ssh_disconnect(session);
        ssh_free(session);
        printf("[*] *Since the session has been passed to a child fork, do some cleaning up at the parent process\n");
    }

    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}