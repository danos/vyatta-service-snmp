/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * usage:
 *
 * When entity-sensor traps are enabled in CLI, snmp-entsensor-trap
 * service will invoke this snmp subagent and sends it varbindlist
 * values for entity sensor traps.
 *
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <signal.h>
#include <poll.h>
#include <errno.h>

#define MODULE_NAME "sensortrap"

static int keep_running;

static RETSIGTYPE stop_agent(int a)
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

static void send_entSensorThresholdNotification(int phyIndex,
						int thresholdType,
						int triggerReading,
						int triggerThreshold,
						char *triggerDescription)
{
	netsnmp_variable_list *notification_vars = NULL;

	oid snmpTrapOID[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
	size_t snmpTrapOID_len = OID_LENGTH(snmpTrapOID);

	oid entSensorThresholdNotification[] =
	    { 1, 3, 6, 1, 4, 1, 74, 1, 32, 2, 0, thresholdType };
	size_t entSensorThresholdNotification_len =
	    OID_LENGTH(entSensorThresholdNotification);
	oid entPhysicalIndex[] = { 1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1 };
	size_t entPhysicalIndex_len = OID_LENGTH(entPhysicalIndex);
	oid entSensorTriggerReading[] =
	    { 1, 3, 6, 1, 4, 1, 74, 1, 32, 2, 1, 1, 1, 7 };
	size_t entSensorTriggerReading_len =
	    OID_LENGTH(entSensorTriggerReading);
	oid entSensorTriggerThreshold[] =
	    { 1, 3, 6, 1, 4, 1, 74, 1, 32, 2, 1, 1, 1, 8 };
	size_t entSensorTriggerThreshold_len =
	    OID_LENGTH(entSensorTriggerThreshold);
	oid entSensorTriggerDescription[] =
	    { 1, 3, 6, 1, 4, 1, 74, 1, 32, 2, 1, 1, 1, 9 };
	size_t entSensorTriggerDescription_len =
	    OID_LENGTH(entSensorTriggerDescription);

	snmp_varlist_add_variable(&notification_vars,
				  snmpTrapOID, snmpTrapOID_len,
				  ASN_OBJECT_ID,
				  (u_char *) entSensorThresholdNotification,
				  entSensorThresholdNotification_len *
				  sizeof(oid));
	snmp_varlist_add_variable(&notification_vars, entPhysicalIndex,
				  entPhysicalIndex_len, ASN_INTEGER,
				  (u_char *) & phyIndex, sizeof(phyIndex));
	snmp_varlist_add_variable(&notification_vars, entSensorTriggerReading,
				  entSensorTriggerReading_len, ASN_INTEGER,
				  (u_char *) & triggerReading,
				  sizeof(triggerReading));
	snmp_varlist_add_variable(&notification_vars, entSensorTriggerThreshold,
				  entSensorTriggerThreshold_len, ASN_INTEGER,
				  (u_char *) & triggerThreshold,
				  sizeof(triggerThreshold));
	snmp_varlist_add_variable(&notification_vars,
				  entSensorTriggerDescription,
				  entSensorTriggerDescription_len,
				  ASN_OCTET_STR, (u_char *) triggerDescription,
				  strlen(triggerDescription));

	send_v2trap(notification_vars);

	snmp_free_varbind(notification_vars);
}

static void parse_sensor_trap_varbinds(char *line)
{
	char *phyIndex, *triggerReading, *triggerThreshold;
	char *triggerDescription, *thresholdType;
	char *p;

	if (line == NULL || *line == '\0') {
		fprintf(stderr, "Invalid varbind data\n");
		return;
	}
	phyIndex = line;
	thresholdType = strchr(line, '|');
	if (!thresholdType) {
		fprintf(stderr, "phyIndex data is missing\n");
		return;
	}
	*thresholdType++ = '\0';
	triggerDescription = strchr(thresholdType, '|');
	if (!triggerDescription) {
		fprintf(stderr, "thresholdType data is missing\n");
		return;
	}
	*triggerDescription++ = '\0';
	triggerReading = strchr(triggerDescription, '|');
	if (!triggerReading) {
		fprintf(stderr, "triggerDescription data is missing\n");
		return;
	}
	*triggerReading++ = '\0';
	triggerThreshold = strchr(triggerReading, '|');
	if (!triggerThreshold) {
		fprintf(stderr, "triggerReading data is missing\n");
		return;
	}
	*triggerThreshold++ = '\0';
	p = strchr(triggerThreshold, '\n');
	if (!p) {
		fprintf(stderr, "triggerThreshold data is missing\n");
		return;
	}
	*p = '\0';

	send_entSensorThresholdNotification(atoi(phyIndex), atoi(thresholdType),
					    atoi(triggerReading),
					    atoi(triggerThreshold),
					    triggerDescription);
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
		parse_sensor_trap_varbinds(line);
	free(line);
}

int main(int argc, char **argv)
{
	int agentx_subagent = 1;
	int c;
	extern char *optarg;
	int use_syslog = 0;
	char *agentx_socket = NULL;
	unsigned int i;

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
			use_syslog = 0;	/* use stderr */
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
		init_master_agent();	/* open the port to listen on (defaults to udp:161) */

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
		struct timeval timeout = {.tv_sec = 1,.tv_usec = 0 };
		fd_set readfds, writefds, exceptfds;
		int numfds;
		int block = 0;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);
		rc = snmp_select_info(&numfds, &readfds, &timeout, &block);
		netsnmp_external_event_info(&numfds, &readfds, &writefds,
					    &exceptfds);
		rc = select(numfds, &readfds, &writefds, &exceptfds,
			    block ? NULL : &timeout);

		if (rc > 0) {
			netsnmp_dispatch_external_events(&rc, &readfds,
							 &writefds, &exceptfds);
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
