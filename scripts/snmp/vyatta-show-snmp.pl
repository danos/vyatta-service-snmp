#! /usr/bin/perl

#
# Copyright (c) 2017-2021 AT&T Intellectual Property.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# Copyright (c) 2007-2010 Vyatta, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Description: Script to display SNMP information
#
use strict;
use warnings;
use Getopt::Long;
use NetAddr::IP;
use Module::Load::Conditional qw[can_load];

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Misc;
use Vyatta::SNMPMisc;

my $vrf_available = can_load(
    modules  => { "Vyatta::VrfManager" => undef },
    autoload => "true"
);
my $SNMPDCFG      = '/etc/snmp/snmpd.conf';
my $SNMPSTATUS    = '/usr/bin/snmpstatus';
my $password_file = '/config/snmp/superuser_pass';
my $SNMPWALKV2    = '/usr/bin/snmpwalk -Os -v2c';
my $INTERNALCOMM  = '__snmpd_internal__';

# generate list of communities in configuration file
sub read_config {
    my %community;

    die "SNMP service is not configured.\n" if ( !-e $SNMPDCFG );

    open( my $cfg, '<', $SNMPDCFG )
      or die "Can't open $SNMPDCFG : $!\n";

    while (<$cfg>) {
        chomp;
        s/#.*$//;
        my @cols = split;
        next
          unless ( $#cols > 0
            && ( $cols[0] eq 'rocommunity' || $cols[0] eq 'rwcommunity' ) );

        my $addr = ( $#cols > 1 ) ? $cols[2] : "0.0.0.0/0";
        $community{ $cols[1] } = NetAddr::IP->new($addr);
    }
    close $cfg;

    return \%community;
}

# expand list of available communities for allowed: tag
sub show_all {
    my $results = "";

    # Source community strings from configd to
    # ensure redaction as required.
    foreach my $comm ( listNodes( "", "community", "tagnode" ) ) {
        $results = join( ' ', $results, $comm );
    }

    print $results, "\n";
    exit 0;
}

sub get_clientaddr {
    my ($comm) = @_;

    $comm = $INTERNALCOMM if ( !defined($comm) || $comm eq "" );
    my $cref       = read_config();
    my %community  = %{$cref};
    my $clientaddr = "";
    foreach my $c ( keys %community ) {
        next if ( $comm eq $INTERNALCOMM && $c eq $INTERNALCOMM );
        next if ( $comm ne $INTERNALCOMM && $c ne $comm );
        if ( $community{$c} ne '0.0.0.0/0' ) {
            my ( $addr, undef ) = split( /\//, $community{$c} );
            $clientaddr = "--clientaddr=$addr";
            return $clientaddr;
        }
    }
    return $clientaddr;
}

# check status of specified community on host
sub status_comm {
    my ( $comm, $host ) = @_;

    my $clientaddr = get_clientaddr($comm);
    status( $comm, $clientaddr, $host );
    status_v3();
}

sub show_mib {
    my $clientaddr = get_clientaddr();
    my $cmd        = "";
    if ($vrf_available) {
        my @vrfs = returnValues( "", "routing-instance" );
        if (@vrfs) {
            my $vrf = shift @vrfs;
            $cmd = "chvrf $vrf";
        }
    }
    my $mib_instances =
      `$cmd $SNMPWALKV2 -c $INTERNALCOMM $clientaddr localhost`;
    die "SNMP walk returned no results.\n" unless $mib_instances;
    my @lines = split /\n/, $mib_instances;
    foreach my $line (@lines) {
        next unless defined($line);
        my ( $minst, $value ) = split /=/, $line;
        print "$minst = $value\n" if ( defined($minst) );
    }
}

sub status_v3 {
    die "SNMP service is not configured.\n" unless ( -e $password_file );
    open( my $file, '<', $password_file )
      or die "Couldn't open $password_file - $!";
    my $superuser_pass = do { local $/; <$file> };
    close $file;
    open( $file, '<', $SNMPDCFG ) or die "Couldn't open $SNMPDCFG - $!";
    my $superuser_login = '';
    while ( my $line = <$file> ) {
        if ( $line =~ /^iquerySecName (.*)$/ ) {
            $superuser_login = $1;
        }
    }
    close $file;

    my @status_cmd;
    if ($vrf_available) {
        my @vrfs = returnValues( "", "routing-instance" );
        if (@vrfs) {
            my $vrf = shift @vrfs;
            @status_cmd = ( 'chvrf', "$vrf" );
        }
    }
    push( @status_cmd,
        $SNMPSTATUS,  '-v3',           '-l',
        'authNoPriv', '-u',            $superuser_login,
        '-A',         $superuser_pass, 'localhost' );
    exec @status_cmd;
    die "Can't exec $SNMPSTATUS : $!";
}

# check status of one community
sub status {
    my ( $community, $clientaddr, $host ) = @_;

    my $snmphost;
    if ( defined($host) && $host ne "" ) {
        $snmphost = $host;
        if ( valid_ipv6_addr($host) ) {
            $snmphost = "udp6:${host}";
        }
    }
    else {
        $snmphost = 'localhost';
    }

    print "Status of SNMP on $snmphost\n";

    my @status_cmd;
    if ($vrf_available) {
        my @vrfs = returnValues( "", "routing-instance" );
        if (@vrfs) {
            my $vrf = shift @vrfs;
            @status_cmd = ( 'chvrf', "$vrf" );
        }
    }
    push( @status_cmd,
        $SNMPSTATUS, '-v2c', '-c', $community, $clientaddr, $snmphost );
    exec @status_cmd;
    die "Can't exec $SNMPSTATUS : $!";
}

sub show_mapping {
    print("\n\nSNMPv1/v2c Community/Context Mapping:\n\n");
    print("Community                   Context\n");
    print("---------                   -------\n");

    foreach my $comm ( listNodes( "", "community", "tagnode" ) ) {
        my $context = returnValue( "community $comm", "context" );
        $context = 'default' unless $context;
        printf( "%-28s%s\n", $comm, $context );
    }
    print "\n";
}

sub print_listen_address {
    my ( $laddrs, $vrf, $rdid ) = @_;
    return unless ( defined($vrf) );

    if ( defined($laddrs) ) {
        my $start = 0;
        foreach my $addr (@$laddrs) {
            my $port = returnValue( "listen-address $addr", "port" );
            $port = '161' unless $port;
            if ( $start == 0 ) {
                printf( "%-28s%-7d%-7s%s\n", $vrf, $rdid, $port, $addr );
                $start = 1;
            }
            else {
                printf( "%-35s%-7s%s\n", "", $port, $addr );
            }
        }
    }
    else {
        printf( "%-28s%d\n", $vrf, $rdid );
    }
}

sub get_vrf_addrs {
    my $laddrs;
    my @addrs = listNodes( "", "listen-address", "tagnode" );
    foreach my $addr (@addrs) {
        my $vrf = returnValue( "listen-address $addr", "routing-instance" );
        $vrf = 'default' unless $vrf;
        push @{ $laddrs->{$vrf} }, $addr;
    }
    return $laddrs;
}

sub show_routing_instance {
    print(
"\n\nRouting Instance SNMP Agent is Listening on for Incoming Requests:\n\n"
    );
    print("Routing-Instance            RDID   Port   Listen Address\n");
    print("-----------------           ----   ----   --------------\n");

    my $vaddrs = get_vrf_addrs();
    my @vrfs   = returnValues( "", "routing-instance" );
    foreach my $vrf (@vrfs) {
        push @{ $vaddrs->{$vrf} }, "" unless ( exists $vaddrs->{$vrf} );
    }
    print_listen_address( undef, 'default', 1 )
      unless ( @vrfs || $vaddrs );
    foreach my $vrf ( keys %{$vaddrs} ) {
        my $rdid = Vyatta::VrfManager::get_vrf_id($vrf);
        print_listen_address( $vaddrs->{$vrf}, $vrf, $rdid );
    }
    print "\n";
}

sub show_trap {
    print("\n\nSNMPv1/v2c Trap-targets:\n\n");
    print("Trap-target                   Port   Community\n");
    print("-----------                   ----   ---------\n");

    foreach my $target ( listNodes( "", "trap-target", "tagnode" ) ) {
        my $port = returnValue( "trap-target $target", "port" );
        my $comm = returnValue( "trap-target $target", "community" );
        if ( length($target) >= 30 ) {
            printf( "%s\n%30s%-7s%s\n", $target, "", $port, $comm );
        }
        else {
            printf( "%-30s%-7s%s\n", $target, $port, $comm );
        }
    }
    print "\n";
}

sub show_routing_instance_trap {
    print("\n\nSNMPv1/v2c Trap-targets:\n\n");
    print("Trap-target                   Port   Routing-Instance Community\n");
    print("-----------                   ----   ---------------- ---------\n");

    foreach my $target ( listNodes( "", "trap-target", "tagnode" ) ) {
        my $port = returnValue( "trap-target $target", "port" );
        my $comm = returnValue( "trap-target $target", "community" );
        my $vrf  = returnValue( "trap-target $target", "routing-instance" );
        $vrf = 'default' unless $vrf;
        if ( length($target) >= 30 ) {
            printf( "%s\n%30s%-7s%-17s%s\n", $target, "", $port, $vrf, $comm );
        }
        else {
            printf( "%-30s%-7s%-17s%s\n", $target, $port, $vrf, $comm );
        }
    }
    print "\n";
}

sub usage {
    print "usage: $0 [--community=name [--host=hostname]]\n";
    print "       $0 --allowed\n";
    print "       $0 --status\n";
    print "       $0 --mapping\n";
    print "       $0 --trap\n";
    print "       $0 --routinginst\n";
    print "       $0 --mib\n";
    exit 1;
}

my ( $host, $community, $allowed, $status, $mapping, $trap, $routinginst,
    $mib );

GetOptions(
    "host=s"      => \$host,
    "community=s" => \$community,
    "allowed"     => \$allowed,
    "status"      => \$status,
    "mapping"     => \$mapping,
    "trap"        => \$trap,
    "routinginst" => \$routinginst,
    "mib"         => \$mib,
) or usage();

show_all() if ($allowed);
status_comm( $community,    $host )       if ( defined($community) );
status_comm( $INTERNALCOMM, "localhost" ) if ( defined($status) );
show_mib() if ( defined($mib) );
if ($vrf_available) {
    show_mapping()               if ( defined($mapping) );
    show_routing_instance_trap() if ( defined($trap) );
    show_routing_instance()      if ( defined($routinginst) );
}
else {
    show_trap() if ( defined($trap) );
}

