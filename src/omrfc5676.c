/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * usage:
 *
 * Use omprog in rsyslog to call this subagent:
 *
 *    module (load="omprog")
 *    $template omrfc5676,"%syslogfacility%,%syslogpriority%,%programname%,%timestamp%,%source%,%syslogtag%,%msg%\n"
 *    *.* action(type="omprog" binary="omrfc5676" template="omrfc5676")
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <signal.h>
#include <poll.h>
#include <errno.h>

#define MODULE_NAME "omrfc5676"

static int keep_running;

static RETSIGTYPE
stop_agent(int a)
{
    keep_running = 0;
}

static void usage(void)
{
    fprintf(stderr,
         "usage: " MODULE_NAME " [-D<tokens>] [-L] [-M] [-x ADDRESS]\n"
         "\t-DTOKEN[,TOKEN,...]\n"
         "\t\tTurn on debugging output for the given TOKEN(s).\n"
         "\t\tWithout any tokens specified, it defaults to printing\n"
         "\t\tall the tokens (which is equivalent to the keyword 'ALL').\n"
         "\t\tYou might want to try ALL for extremely verbose output.\n"
         "\t\tNote: You can't put a space between the -D and the TOKENs.\n"
         "\t-M\tRun as a normal SNMP Agent instead of an AgentX sub-agent.\n"
         "\t-x ADDRESS\tconnect to master agent at ADDRESS (default NETSNMP_AGENTX_SOCKET).\n"
         "\t-L\tDo not open a log file; print all messages to stderr.\n");
    exit(0);
}

static void send_syslogMsgNotification(int facility,
                                       int priority,
                                       char *timestamp,
                                       char *hostname,
                                       char *appname,
                                       char *procid,
                                       char *msgid,
                                       char *msg)
{
    netsnmp_variable_list *notification_vars = NULL;

    oid    snmpTrapOID[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
    size_t snmpTrapOID_len = OID_LENGTH(snmpTrapOID);

    oid     syslogMsgNotification[] = { 1, 3, 6, 1, 2, 1, 192, 0, 1 };
    size_t  syslogMsgNotification_len = OID_LENGTH(syslogMsgNotification);
    oid     syslogMsgFacility[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 2 };
    size_t  syslogMsgFacility_len = OID_LENGTH(syslogMsgFacility);
    oid     syslogMsgSeverity[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 3 };
    size_t  syslogMsgSeverity_len = OID_LENGTH(syslogMsgSeverity);
    oid     syslogMsgVersion[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 4 };
    size_t  syslogMsgVersion_len = OID_LENGTH(syslogMsgVersion);
    oid     syslogMsgTimeStamp[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 5 };
    size_t  syslogMsgTimeStamp_len = OID_LENGTH(syslogMsgTimeStamp);
    oid     syslogMsgHostName[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 6 };
    size_t  syslogMsgHostName_len = OID_LENGTH(syslogMsgHostName);
    oid     syslogMsgAppName[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 7 };
    size_t  syslogMsgAppName_len = OID_LENGTH(syslogMsgAppName);
    oid     syslogMsgProcID[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 8 };
    size_t  syslogMsgProcID_len = OID_LENGTH(syslogMsgProcID);
    oid     syslogMsgMsgID[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 9 };
    size_t  syslogMsgMsgID_len = OID_LENGTH(syslogMsgMsgID);
    oid     syslogMsgSDParams[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 10 };
    size_t  syslogMsgSDParams_len = OID_LENGTH(syslogMsgSDParams);
    oid     syslogMsgMsg[] = { 1, 3, 6, 1, 2, 1, 192, 1, 2, 1, 11 };
    size_t  syslogMsgMsg_len = OID_LENGTH(syslogMsgMsg);

    int SYSLOG_MSG_VERSION = 1;
    int zero = 0;

    snmp_varlist_add_variable(&notification_vars,
                              snmpTrapOID, snmpTrapOID_len,
                              ASN_OBJECT_ID,
                              (u_char *) syslogMsgNotification,
                              syslogMsgNotification_len * sizeof(oid));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgFacility, syslogMsgFacility_len,
                              ASN_INTEGER,
                              (u_char *) &facility, sizeof(facility));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgSeverity, syslogMsgSeverity_len,
                              ASN_INTEGER,
                              (u_char *) &priority, sizeof(priority));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgVersion, syslogMsgVersion_len,
                              ASN_INTEGER,
                              (u_char *) &SYSLOG_MSG_VERSION,
                              sizeof(SYSLOG_MSG_VERSION));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgTimeStamp, syslogMsgTimeStamp_len,
                              ASN_OCTET_STR,
                              (u_char *) timestamp, strlen(timestamp));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgHostName, syslogMsgHostName_len,
                              ASN_OCTET_STR,
                              (u_char *) hostname, strlen(hostname));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgAppName, syslogMsgAppName_len,
                              ASN_OCTET_STR,
                              (u_char *) appname, strlen(appname));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgProcID, syslogMsgProcID_len,
                              ASN_OCTET_STR,
                              (u_char *) procid, strlen(procid));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgMsgID, syslogMsgMsgID_len,
                              ASN_OCTET_STR,
                              (u_char *) msgid, strlen(msgid));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgSDParams, syslogMsgSDParams_len,
                              ASN_INTEGER,
                              (u_char *) &zero, sizeof(zero));
    snmp_varlist_add_variable(&notification_vars,
                              syslogMsgMsg, syslogMsgMsg_len,
                              ASN_OCTET_STR,
                              (u_char *) msg, strlen(msg));

    send_v2trap(notification_vars);

    snmp_free_varbind(notification_vars);
}

static void parse_syslog(char *line)
{
        char *facility, *msg, *priority, *progname;
        char *source, *tag, *timestamp;
        char *procid = "";
        char *p;

        facility = line;
        priority = strchr(line, ',');
        if (!priority) {
                fprintf(stderr, "missing priority\n");
                return;
        }
        *priority++ = '\0';
        progname = strchr(priority, ',');
        if (!progname) {
                fprintf(stderr, "missing progname\n");
                return;
        }
        *progname++ = '\0';
        timestamp = strchr(progname, ',');
        if (!timestamp) {
                fprintf(stderr, "missing timestamp\n");
                return;
        }
        *timestamp++ = '\0';
        source = strchr(timestamp, ',');
        if (!source) {
                fprintf(stderr, "missing source\n");
                return;
        }
        *source++ = '\0';
        tag = strchr(source, ',');
        if (!tag) {
                fprintf(stderr, "missing tag\n");
                return;
        }
        *tag++ = '\0';
        msg = strchr(tag, ',');
        if (!msg) {
                fprintf(stderr, "missing msg\n");
                return;
        }
        *msg++ = '\0';
        p = strchr(msg, '\n');
        *p = '\0';

        /* extract pid from the tag (if possible) */
        p = strchr(tag, '[');
        if (p) {
            procid = ++p;
            p = strchr(procid, ']');
            *p = '\0';
        }

        send_syslogMsgNotification(atoi(facility), atoi(priority), timestamp,
                                   source, progname, procid, "", msg);
}

static void stdin_ready_cb(int fd, void *data)
{
        char *line = NULL;
	size_t n = 0;

        if (feof(stdin)) {
                keep_running = 0;
                return;
        }
        if (getline(&line, &n, stdin))
                parse_syslog(line);
	free(line);
}

int main(int argc, char **argv)
{
    int             agentx_subagent = 1;
    int             c;
    extern char    *optarg;
    int             use_syslog = 0;
    char           *agentx_socket = NULL;
    unsigned int    i;

    while ((c = getopt(argc, argv, "D:LMx:")) != EOF)
        switch (c) {
        case 'D':
            debug_register_tokens(optarg);
            snmp_set_do_debugging(1);
            break;
        case 'M':
            agentx_subagent = 0;
            break;
        case 'L':
            use_syslog = 0;     /* use stderr */
            break;
        case 'x':
            agentx_socket = optarg;
            break;
        default:
            fprintf(stderr, "unknown option %c\n", c);
            usage();
        }

    /* we're an agentx subagent? */
    if (agentx_subagent) {
        /* make us a agentx client */
        netsnmp_enable_subagent();
        if (NULL != agentx_socket)
            netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                                  NETSNMP_DS_AGENT_X_SOCKET,
                                  agentx_socket);
    }

    snmp_disable_log();
    if (use_syslog)
        snmp_enable_calllog();
    else
        snmp_enable_stderrlog();

    /* initialize tcpip, if necessary */
    SOCK_STARTUP;

    /* initialize the agent library */
    init_agent(MODULE_NAME);

    /* initialize mib code */
    /* nothing to do */

    /* read .conf files.  */
    init_snmp(MODULE_NAME);

    /* If we're going to be a snmp master agent, initialize the ports */
    if (!agentx_subagent)
        init_master_agent();    /* open the port to listen on (defaults to udp:161) */

    /* rsyslogd may signal us to stop */
    keep_running = 1;
    signal(SIGTERM, stop_agent);
    signal(SIGINT, stop_agent);
    signal(SIGHUP, stop_agent);

    /* register callback when stdin is ready */
    register_readfd(STDIN_FILENO, stdin_ready_cb, NULL);

    /* main loop when using external events */
    while (keep_running) {
        int rc;
        struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
        fd_set readfds, writefds, exceptfds;
        int numfds;
        int block = 0;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        rc = snmp_select_info(&numfds, &readfds, &timeout, &block);
          netsnmp_external_event_info(&numfds, &readfds, &writefds, &exceptfds);
        rc = select(numfds, &readfds, &writefds, &exceptfds, block ? NULL : &timeout);

        if (rc > 0) {
                netsnmp_dispatch_external_events(&rc, &readfds, &writefds, &exceptfds);
                snmp_read(&readfds);
        } else if (rc == 0) {
                snmp_timeout();
        } else {
                snmp_log_perror("select");
                keep_running = 0;
        }

        snmp_store_if_needed();
        run_alarms();
        netsnmp_check_outstanding_agent_requests();
    }

    snmp_shutdown(MODULE_NAME);
    SOCK_CLEANUP;

    exit(0);
}
