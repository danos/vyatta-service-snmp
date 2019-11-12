#!/usr/bin/perl
#
# Module: vyatta-snmp.pl
#
# Copyright (c) 2017-2019 AT&T Intellectual Property.
# Copyright (c) 2014-2017 Brocade Communications Systems, Inc.
# Copyright (c) 2007-2010 Vyatta, Inc.
# All Rights Reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Description: Script to glue vyatta cli to snmp daemon
#

use strict;
use warnings;

use lib "/opt/vyatta/share/perl5/";
use Module::Load::Conditional qw[can_load];
use Vyatta::Config;
use Vyatta::Misc;
use NetAddr::IP;
use Getopt::Long;
use File::Copy;
use Socket;
use Socket6;
use Config::IniFiles;

use constant SO_BINDTODEVICE => 25;

my $vrf_available = can_load( modules => { "Vyatta::VrfManager" => undef },
    autoload => "true" );
my $mibdir                      = '/opt/vyatta/share/snmp/mibs';
my $snmp_conf                   = '/etc/snmp/snmpd.conf';
my $snmp_client                 = '/etc/snmp/snmp.conf';
my $snmp_tmp                    = "/tmp/snmpd.conf.$$";
my $snmp_snmpv3_user_conf       = '/usr/share/snmp/snmpd.conf';
my $snmp_snmpv3_createuser_conf = '/var/lib/snmp/snmpd.conf';
my $local_agent                 = 'unix:/var/run/snmpd.socket';
my $password_file               = '/config/snmp/superuser_pass';
my $trapd_cfg                   = '/etc/snmp/trapd.ini';
my $default_sysobjectid         = '1.3.6.1.4.1.74.1.32';
my $notifications_args_file     = '/run/snmpd/vyatta-entity-state-traps-args';

my $config = new Vyatta::Config;

my $snmp_level = 'service snmp';

my @trapd_services = ('vyatta-ipsec-trapd');

# Are we using routing-domain VRF implementation, as opposed to VRF
# master implementation?
sub using_rd_vrf {
    return 1
        if -f "/proc/self/rtg_domain";
    return 0;
}

sub get_rdid_or_vrfname {
    my $vrf = shift;

    # Use ID for RD, name for VRF master
    if ( using_rd_vrf() ) {
        return Vyatta::VrfManager::get_vrf_id($vrf);
    } else {
        return $Vyatta::VrfManager::VRFMASTER_PREFIX . $vrf;
    }
}

sub snmp_running {
    open( my $pidf, '<', "/var/run/snmpd.pid" )
      or return;
    my $pid = <$pidf>;
    close $pidf;

    chomp $pid;
    my $exe = readlink "/proc/$pid/exe";

    return ( defined($exe) && $exe eq "/usr/sbin/snmpd" );
}

sub snmp_stop {
    system("systemctl stop snmpd > /dev/null 2>&1");
    system("systemctl stop snmptrapd > /dev/null 2>&1");

    snmp_trapd_service_start_stop();
}

sub snmp_start {

    #validating the routing-instance to listen on for
    # incoming requests
    validate_listen_routing_instance() if $vrf_available;

    #validating the listen address
    validate_listen_address();

    #validating routing-instance for trap-targets
    validate_trap_routing_instance() if $vrf_available;

    # we must stop snmpd first for creating vyatta user
    system("systemctl stop snmpd > /dev/null 2>&1");
    open( my $fh, '>', $snmp_tmp )
      or die "Couldn't open $snmp_tmp - $!";

    select $fh;
    snmp_get_constants();
    snmp_get_values();
    snmp_get_disablesnmpv3();
    snmp_get_contexts() if $vrf_available;
    snmp_get_authtrap();
    snmp_get_traps();
    snmp_get_views();
    snmp_get_overrides();
    snmp_get_sensortrap();
    snmp_get_storm_control_trap();
    close $fh;
    select STDOUT;

    snmp_client_config();

    move( $snmp_tmp, $snmp_conf )
      or die "Couldn't move $snmp_tmp to $snmp_conf - $!";

    snmp_trapd_service_start_stop();
}

sub get_version {
    my $version = "unknown-version";

    my $cmd = "/opt/vyatta/bin/opc show version";
    if ( open(my $cmdout, '-|', "$cmd") ) {
        while (<$cmdout>) {
            chomp;
            if (m/^Version\s*:\s*(.*)$/) {
                $version = $1;
                last;
            }
        }
        close $cmdout;
    }
    return $version;
}

# convert address to snmpd transport syntax
sub transport_syntax {
    my ( $addr, $port ) = @_;
    my $ip = new NetAddr::IP $addr;
    die "$addr: not a valid IP address" unless $ip;

    my $version = $ip->version();
    return "udp:$addr:$port"    if ( $version == 4 );
    return "udp6:[$addr]:$port" if ( $version == 6 );
    die "$addr: unknown IP version $version";
}

# Test if IPv6 is possible by opening a socket
sub ipv6_disabled {
    socket( my $s, PF_INET6, SOCK_DGRAM, 0 )
      or return 1;
    close($s);
    return;
}

# Test if address is local to VRF
sub is_vrf_local_address {
    my ($addr, $vrf) = @_;
    die "$addr: invalid routing-instance $vrf"
      unless defined($vrf);
    my $ip   = new NetAddr::IP $addr;
    die "$addr: not a valid IP address"
      unless $ip;

    my ( $pf, $sockaddr );
    if ( $ip->version() == 4 ) {
        $pf = PF_INET;
        $sockaddr = sockaddr_in( 0, $ip->aton() );
    } else {
        $pf = PF_INET6;
        $sockaddr = sockaddr_in6( 0, $ip->aton() );
    }

    socket( my $sock, $pf, SOCK_STREAM, 0 )
      or die "socket failed\n";

    setsockopt( $sock, SOL_SOCKET, SO_BINDTODEVICE, pack("Z*", "vrf$vrf" ) )
      or die "setsockopt failed\n";

    my $ret = bind( $sock, $sockaddr );
    close( $sock );
    return $ret;
}

# Check if the configured listen address
# is present on the system
sub validate_listen_address {
    $config->setLevel('service snmp listen-address');
    my @vrfs = $config->returnValues('routing-instance') if $vrf_available;
    my @address = $config->listNodes();

    if (@address) {

        #Check if the listen address is a local address
        foreach my $addr (@address) {
            if ($vrf_available && @vrfs) {
                my $vrf = shift @vrfs;
                $vrf = get_rdid_or_vrfname($vrf);
                die "Non-existent listen address $addr in routing-instance $vrf\n"
                  unless ( is_vrf_local_address($addr, $vrf) );
            } else {
                die "Non-existent listen address $addr\n"
                  unless ( is_local_address($addr) );
            }
        }
    }
}

# Check if the configured listen routing-instance
# has valid rdid
sub validate_listen_routing_instance {
    if ( $vrf_available ) {
        $config->setLevel('service snmp routing-instance');
        my @vrfs = $config->returnValues();
        return unless @vrfs;

        my $vrf = shift @vrfs;
        die "Invalid routing-instance to listen on for incoming requests: $vrf\n"
          unless ( Vyatta::VrfManager::get_vrf_id($vrf) );
    }
}

# Check if the configured trap target routing-instance
# has valid rdid
sub validate_trap_routing_instance {
    my @trap_targets;

    if ( $vrf_available ) {
        $config->setLevel($snmp_level);
        @trap_targets = $config->listNodes("trap-target");
        return unless @trap_targets;

        foreach my $trap_target (@trap_targets) {
            my $vrf = $config->returnValue("trap-target $trap_target routing-instance");
            next unless defined($vrf);

            die "Invalid routing-instance $vrf for trap-target $trap_target\n"
              unless ( Vyatta::VrfManager::get_vrf_id($vrf) );
        }

        @trap_targets = $config->listNodes("v3 trap-target");
        return unless @trap_targets;

        foreach my $trap_target (@trap_targets) {
            my $vrf = $config->returnValue("trap-target $trap_target routing-instance");
            next unless defined($vrf);

            die "Invalid routing-instance $vrf for v3 trap-target $trap_target\n"
              unless ( Vyatta::VrfManager::get_vrf_id($vrf) );
        }
    }
}

# Find SNMP agent listening addresses
sub get_listen_address {
    my @listen;
    my @vrfs;
    my $localhost = new NetAddr::IP('localhost');

    $config->setLevel($snmp_level);
    @vrfs = $config->returnValues('routing-instance') if $vrf_available;
    my @address = $config->listNodes('listen-address');

    if (@address) {
        foreach my $addr (@address) {
            my $port = $config->returnValue("listen-address $addr port");
            $port = '161' unless $port;
            next if ($addr eq '127.0.0.1' && $port eq '161');
            if ($vrf_available && @vrfs) {
                my $vrf = shift @vrfs;
                $vrf = get_rdid_or_vrfname($vrf);
                my $addr_port = transport_syntax( $addr, $port );
                @listen = ("$addr_port:$vrf");
            } else {
                push @listen, transport_syntax( $addr, $port );
            }
        }

        # default listener on localhost
        if ($vrf_available && @vrfs) {
            my $vrf = shift @vrfs;
            $vrf = get_rdid_or_vrfname($vrf);
            push @listen, join( '', 'udp:', $localhost->addr(), ':161', ':', $vrf );
        } else {
            push @listen, join( '', 'udp:', $localhost->addr(), ':161' );
        }    
    } else {

        # default if no address specified
        if ($vrf_available && @vrfs) {
            my $vrf = shift @vrfs;
            $vrf = get_rdid_or_vrfname($vrf);
            @listen = ("udp:161:$vrf");
            push @listen, "udp6:161:$vrf" unless ipv6_disabled();
        } else {
            @listen = ('udp:161');
            push @listen, 'udp6:161' unless ipv6_disabled();
        }
    }
    return @listen;
}

sub snmp_get_constants {
    my $version = get_version();
    my $now     = localtime;
    my @addr    = get_listen_address();

    # add local unix domain target for use by operational commands
    unshift @addr, $local_agent;

    print "# autogenerated by vyatta-snmp.pl on $now\n";
    print "sysDescr Vyatta $version\n";
    print "sysServices 14\n";
    print "master agentx\n";    # maybe needed by lldpd
    print "agentXSocket tcp:localhost:705\n";    # setting listening socket.
    print "agentaddress ", join( ',', @addr ), "\n";
    print "agentgroup vyattacfg\n";
    print "agentXTimeout 5\n";

    # Support for NAT MIB (RFC 4008)
    print "pass_persist .1.3.6.1.2.1.123.1 /opt/vyatta/sbin/vyatta-nat-mib.pl\n";

    # Support for AT&T QoS MIB
    print "pass_persist .1.3.6.1.4.1.74.1.32.1 /opt/vyatta/sbin/vyattaqosmib.pl\n";

    # Support for AT&T Storm Control MIB
    print "pass_persist .1.3.6.1.4.1.74.1.32.4 /opt/vyatta/sbin/vyatta-storm-ctl-mib.pl\n";
}

# generate a random character hex string
sub randhex {
    my $length = shift;
    return join "", map { unpack "H*", chr( rand(256) ) } 1 .. ( $length / 2 );
}

# output snmpd.conf file syntax for community
sub print_community {
    my ( $community ) = @_;
    $config->setLevel("service snmp community $community");
    my $ro = $config->returnValue('authorization');
    $ro = 'ro' unless $ro;

    my @clients  = $config->returnValues('client');
    my @networks = $config->returnValues('network');
    my @restriction = ( @clients, @networks );

    my $view = $config->returnValue('view');
    my $context = $config->returnValue('context');

    $view = "-V $view" if defined($view);
    $view = "$view $context" if (defined($view) && defined($context));

    if ( !@restriction ) {
        my $comm = "community $community";
        my $comm6 = "community6 $community";
        if ( defined $view ) {
            $comm = "$comm default $view";
            $comm6 = "$comm6 default $view";
        }
        print "$ro$comm\n";
        print "$ro$comm6\n" unless ipv6_disabled();
        return;
    }

    foreach my $addr (@restriction) {
        my $ip = new NetAddr::IP $addr;
        die "$addr: Not a valid IP address" unless $ip;

        my $comm = "community $community $addr";
        my $comm6 = "community6 $community $addr";
        if ( defined $view ) {
            $comm = "$comm $view";
            $comm6 = "$comm6 $view";
        }
        if ( $ip->version() == 4 ) {
            print "$ro$comm\n";
        } elsif ( $ip->version() == 6 ) {
            print "$ro$comm6\n";
        } else {
            die "$addr: bad IP version ", $ip->version();
        }
    }
}

sub snmp_get_values {
    $config->setLevel($snmp_level);

    # internal community string for 'show snmp mib' command
    print "rocommunity __snmpd_internal__ localhost\n";
    print "rocommunity6 __snmpd_internal__ localhost\n";

    my @communities = $config->listNodes("community");
    foreach my $community (@communities) {
        print_community( $community );
    }

    $config->setLevel($snmp_level);

    my $sysobjectid = $config->returnValue("sysobjectid");
    if ( ! defined $sysobjectid ) {
        $sysobjectid = get_sysobjectid();
    }
    printf "sysObjectID %s\n", $sysobjectid;

    my $contact = $config->returnValue("contact");
    if ( defined $contact ) {
        print "syscontact \"$contact\" \n";
    } else {
        print "syscontact Unknown\n";
    }

    my $description = $config->returnValue("description");
    if ( defined $description ) {
        print "sysdescr \"$description\" \n";
    }

    my $location = $config->returnValue("location");
    if ( defined $location ) {
        print "syslocation \"$location\" \n";
    }
}

# write views from vyatta config to snmpd_conf
sub snmp_get_views {
    print "# views \n";
    $config->setLevel($snmp_level);
    foreach my $view ( $config->listNodes("view") ) {
        foreach my $oid ( $config->listNodes("view $view oid") ) {
            my $mask = $config->returnValue("view $view oid $oid mask");
            $mask = '' unless $mask;
            if ( $config->exists("view $view oid $oid exclude") ) {
                print "view $view excluded .$oid $mask\n";
            }
            else {
                print "view $view included .$oid $mask\n";
            }
        }
    }
    print "\n";
}

# Create any overrides we need based on the current configuration
sub snmp_get_overrides {
    print "# overrides\n";
    $config->setLevel($snmp_level);
    if (!$config->exists("notification ping all")) {
        print "override .1.3.6.1.2.1.80.1.2.1.13.3 octet_str \"\"\n";
    }
    print "\n";
}

# write contexts from vyatta config to snmpd_conf
sub snmp_get_contexts {
    if ( $vrf_available ) {
print
"#contexts\n#             context contextID\n";
        my $rconfig = new Vyatta::Config;
        foreach my $vrf ( $rconfig->listNodes("routing routing-instance") ) {
            my $vrfmaster = get_rdid_or_vrfname($vrf);
            print "context $vrf $vrfmaster\n";
        }
        print "\n";
     }
}

sub get_trap_target_address {
    my ( $addr, $port, $rdid ) = @_;
    my $ip = new NetAddr::IP $addr;
    die "$addr: not a valid IP address" unless $ip;

    my $version = $ip->version();
    if ( $version == 4 ) {
        $addr = "udp:$addr";
    } elsif ( $version == 6 ) {
        $addr = "udp6:[$addr]";
    } else {
        die "$addr: unknown IP version $version";
    }
    $port = '162' unless $port;
    $addr = "$addr:$port";
    $addr = "$addr:$rdid" if ($vrf_available && $rdid);
    return $addr;
}

sub snmp_get_traps {
    $config->setLevel($snmp_level);

    # linkUp/Down configure the Event MIB tables to monitor
    # the ifTable for network interfaces being taken up or down
    # for making internal queries to retrieve any necessary information

    # create an internal snmpv3 user of the form 'vyattaxxxxxxxxxxxxxxxx'
    my $vyatta_user = "vyatta" . randhex(16);
    snmp_create_snmpv3_user($vyatta_user);
    snmp_write_snmpv3_user($vyatta_user);
    print "iquerySecName $vyatta_user\n";

    # Modified from the default linkUpDownNotification
    # to include more OIDs and poll more frequently
    print <<EOF;
notificationEvent  linkUpTrap    linkUp   ifIndex ifName ifAlias ifType ifAdminStatus ifOperStatus
notificationEvent  linkDownTrap  linkDown ifIndex ifName ifAlias ifType ifAdminStatus ifOperStatus
monitor  -r 10 -e linkUpTrap   "Generate linkUp" ifOperStatus != 2
monitor  -r 10 -e linkDownTrap "Generate linkDown" ifOperStatus == 2
EOF

    my $need_trapd = 0;

    my @trap_targets = $config->listNodes("trap-target");
    foreach my $trap_target (@trap_targets) {
        my $port = $config->returnValue("trap-target $trap_target port");
        my $community =
          $config->returnValue("trap-target $trap_target community");
        my $addr_vrf;
        my $vrf =
              $config->returnValue("trap-target $trap_target routing-instance");
        $addr_vrf = get_rdid_or_vrfname($vrf)
            if $vrf_available && defined($vrf);

        my $addr = get_trap_target_address($trap_target, $port, $addr_vrf);
        print "trap2sink";
        print " -n $vrf"     if ($vrf_available && $vrf);
        print " $addr";
        print " $community" if $community;
        print "\n";
    }

    if ($config->exists("notification-to-syslog enable")) {
        print "\ntrap2sink udp:localhost:162 __internal__\n\n";
        $need_trapd = 1;
    }

    my $trapd_status;
    if ($need_trapd) {
        $trapd_status = "TRAPDRUN=yes";
    } else {
        $trapd_status = "TRAPDRUN=no";
    }

    open( my $fh, '<', "/etc/default/snmptrapd" )
      or die "Couldn't open /etc/default/snmpd - $!";
    my @lines = <$fh>;
    close $fh;
    open( $fh, '>', "/etc/default/snmptrapd" )
      or die "Couldn't open /etc/default/snmpd - $!";

    foreach my $line (@lines) {
        $line =~ s/^TRAPDRUN=.*/$trapd_status/g;
        print $fh $line;
    }
    close $fh;

    if ($need_trapd) {
        open( $fh, '>', "/etc/snmp/snmptrapd.conf" )
          or die "Couldn't open /etc/snmp/snmptrapd.conf - $!";
        print $fh "authCommunity execute __internal__\n";
        my $facility = $config->returnValue("notification-to-syslog facility");
        my $level = $config->returnValue("notification-to-syslog level");
        print $fh "traphandle default /opt/vyatta/sbin/notification-to-syslog -p $facility.$level\n";
        close $fh;
        system("systemctl restart snmptrapd > /dev/null 2>&1");
    } else {
        system("systemctl stop snmptrapd > /dev/null 2>&1");
    }
}

# Configure SNMP client parameters
sub snmp_client_config {
    $config->setLevel($snmp_level);
    open( my $cf, '>', $snmp_client )
      or die "Couldn't open $snmp_client - $!";

    my $now     = localtime;
    print {$cf} "# autogenerated by vyatta-snmp.pl on $now\n";

    my $trap_source = $config->returnValue('trap-source');
    print {$cf} "clientaddr $trap_source\n" if ($trap_source);
    print {$cf} "timeout 5\n";
    close $cf;
}

sub snmp_create_snmpv3_user {

    my $vyatta_user = shift;
    my $passphrase  = randhex(32);

    my $createuser = "createUser $vyatta_user MD5 \"$passphrase\" DES";
    open( my $fh, '>', $snmp_snmpv3_createuser_conf )
      || die "Couldn't open $snmp_snmpv3_createuser_conf - $!";
    print $fh $createuser;
    close $fh;

    open( my $pass_file, '>', $password_file )
      || die "Couldn't open $password_file - $!";
    print $pass_file $passphrase;
    close $pass_file;
}

sub snmp_write_snmpv3_user {

    my $vyatta_user = shift;
    my $user        = "rwuser $vyatta_user\n";
    open( my $fh, '>', $snmp_snmpv3_user_conf )
      || die "Couldn't open $snmp_snmpv3_user_conf - $!";
    print $fh $user;
    close $fh;
}

# Check if Storm Control traps are enabled
# and start the service to monitor Storm
# Control events and send traps.
sub snmp_get_storm_control_trap {
    $config->setLevel($snmp_level);

    if ( $config->exists("notification storm-control") ) {
        system("systemctl start vyatta-storm-ctl-notifier");
    } else {
        system("systemctl stop vyatta-storm-ctl-notifier");
    }
}

# Check if entity sensor traps are enabled
# and start snmp-entsensor-trap service to
# monitor IPMI SEL and send traps
sub snmp_get_sensortrap {
    $config->setLevel($snmp_level);
    my @args = ();

    push @args, "sensor"
      if ( $config->exists("notification entity-sensor all") );
    push @args, "state"
      if ( $config->exists("notification entity-state all") );
    if ( scalar(@args) == 0 ) {
        unlink($notifications_args_file);
    } else {
        open( my $fh, '>', $notifications_args_file )
          or die "Couldn't open $notifications_args_file - $!";
        foreach my $arg (@args) {
            print $fh "$arg\n";
        }
        close $fh;
    }
    system("systemctl restart snmp-entsensor-trap.service");
}

# Check if v2/v3 auth failure traps are enabled
sub snmp_get_authtrap {
    $config->setLevel($snmp_level);

    if ( $config->exists("notification auth-failure all") ) {
        print "authtrapenable 1\n";
    }
}

# write disablesnmpv3 flag to snmpd.conf
# disablesnmpv3 is true if vyatta config has no v3 configuration,
# false otherwise.
sub snmp_get_disablesnmpv3 {
    $config->setLevel($snmp_level);

    if ( !$config->exists("v3") ) {
        print "disablesnmpv3 true\n";
    }
}

sub snmp_trapd_service_start_stop {
    $config->setLevel($snmp_level);
    if ( $config->exists("description") &&
            $config->exists("trap-target") ) {
        my $inifile = Config::IniFiles->new();
        unless ( defined $inifile->SetFileName($trapd_cfg) ) {
            print "Error opening new Config::IniFiles $trapd_cfg";
            return;
        };

        my @default_communities = $config->listNodes('community');
        if ( scalar @default_communities != 0 ) {
            $inifile->newval('general', 'community', join(" ", @default_communities));
        }

        my $descr = $config->returnValue('description');
        $inifile->newval('general', 'description', $descr);

        my $source = $config->returnValue('trap-source');
        if ( defined $source ) {
            $inifile->newval('general', 'trap-source', $source);
        }

        my @targets = $config->listNodes('trap-target');

        foreach my $target (@targets) {
            $inifile->newval("trap-target $target", 'address', $target);

            my $port = $config->returnValue("trap-target $target port");
            if ( defined $port ) {
                $inifile->newval("trap-target $target", 'port', $port);
            }

            my $community = $config->returnValue("trap-target $target community");
            if (! defined $community) {
                # If there is only one global community, then that's an
                # unambiguous default. If there are multiple ones, then
                # one needs to be explicitly bound to the trap-target(s).
                if ( scalar @default_communities != 1 ) {
                    print "Need community set for trap-target $target";
                    next;
                }
            } else {
                $inifile->newval("trap-target $target", 'community', $community);
            }
        }

        $inifile->SetWriteMode('644');
        unless ( defined $inifile->RewriteConfig() ) {
            print "Error writing trapd configuration to $trapd_cfg";
            return;
        }

        for my $service (@trapd_services) {
            system("systemctl restart $service > /dev/null 2>&1");
        }
    } else {
        for my $service (@trapd_services) {
            system("systemctl stop $service > /dev/null 2>&1");
        }
    }
}

# Use dmidecode to determine the OID string to use for this platform.
# If we can't determine one, fall back to the default.

sub get_sysobjectid {
    my $what_am_i = `/opt/vyatta/bin/vyatta-platform-util --what-am-i`;
    my $sysobjectid = $default_sysobjectid;

    chomp($what_am_i);
    if ($what_am_i eq "att.flexware-xs") {
        $sysobjectid = '1.3.6.1.4.1.74.1.31.1';
    } elsif ($what_am_i eq "att.flexware-s") {
        $sysobjectid = '1.3.6.1.4.1.74.1.31.2';
    } elsif ($what_am_i eq "att.flexware-m") {
        $sysobjectid = '1.3.6.1.4.1.74.1.31.3';
    } elsif ($what_am_i eq "att.flexware-l") {
        $sysobjectid = '1.3.6.1.4.1.74.1.31.4';
    }

    return $sysobjectid;
}

#
# main
#
my $update_snmp;
my $stop_snmp;

GetOptions(
    "update-snmp!" => \$update_snmp,
    "stop-snmp!"   => \$stop_snmp
);

snmp_start() if ($update_snmp);
snmp_stop()  if ($stop_snmp);
