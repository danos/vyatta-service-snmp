#! /usr/bin/perl
#
# Copyright (c) 2017-2021 AT&T Intellectual Property.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

use strict;
use warnings;
use Getopt::Long;
use Module::Load::Conditional qw[can_load];

use lib "/opt/vyatta/share/perl5/";
use Vyatta::SNMPMisc;

my $vrf_available = can_load(
    modules  => { "Vyatta::VrfManager" => undef },
    autoload => "true"
);

sub show_group {
    print("\n\nSNMPv3 Groups:\n\n");
    print("Group               View\n");
    print("-----               ----\n");

    foreach my $group ( listNodes( "v3", "group", "tagnode" ) ) {
        my $view = returnValue( "v3 group $group", "view" );
        my $mode = returnValue( "v3 group $group", "mode" );
        if ( length($group) >= 20 ) {
            printf( "%s\n%-20s%s\n", $group, "", "$view($mode)" );
        }
        else {
            printf( "%-20s%s\n", $group, "$view($mode)" );
        }
    }
    print "\n";
}

sub show_user {
    print("\n\nSNMPv3 Users:\n\n");
    print("User                Auth Priv Mode Group\n");
    print("----                ---- ---- ---- -----\n");

    foreach my $user ( listNodes( "v3", "user", "tagnode" ) ) {
        my $auth  = returnValue( "v3 user $user auth",    "type" );
        my $priv  = returnValue( "v3 user $user privacy", "type" );
        my $mode  = returnValue( "v3 user $user",         "mode" );
        my $group = returnValue( "v3 user $user",         "group" );
        if ( length($user) >= 20 ) {
            printf( "%s\n%-20s%-5s%-5s%-5s%s\n",
                $user, "", $auth, $priv, $mode, $group );
        }
        else {
            printf( "%-20s%-5s%-5s%-5s%s\n",
                $user, $auth, $priv, $mode, $group );
        }
    }
    print "\n";
}

sub show_trap {
    print("\n\nSNMPv3 Trap-targets:\n\n");
    print(
"Trap-target                   Port   Protocol Auth Priv Type   EngineID              User\n"
    );
    print(
"-----------                   ----   -------- ---- ---- ----   --------              ----\n"
    );

    foreach my $trap ( listNodes( "v3", "trap-target", "tagnode" ) ) {
        my $auth = returnValue( "v3 trap-target $trap auth",    "type" );
        my $priv = returnValue( "v3 trap-target $trap privacy", "type" );
        my $type = returnValue( "v3 trap-target $trap",         "type" );
        my $port = returnValue( "v3 trap-target $trap",         "port" );
        my $user = returnValue( "v3 trap-target $trap",         "user" );
        my $protocol = returnValue( "v3 trap-target $trap", "protocol" );
        my $engineid = returnValue( "v3 trap-target $trap", "engineid" );

        if ( length($trap) >= 30 ) {
            printf(
                "%s\n%-30s%-7s%-9s%-5s%-5s%-7s%-22s%s\n",
                $trap, "",    $port,     $protocol, $auth,
                $priv, $type, $engineid, $user
            );
        }
        else {
            printf(
                "%-30s%-7s%-9s%-5s%-5s%-7s%-22s%s\n",
                $trap, $port, $protocol, $auth,
                $priv, $type, $engineid, $user
            );
        }
    }
    print "\n";
}

sub show_routing_instance_trap {
    print("\n\nSNMPv3 Trap-targets:\n\n");
    print(
"Trap-target                   Port   Protocol Auth Priv Type   EngineID              Routing-Instance User\n"
    );
    print(
"-----------                   ----   -------- ---- ---- ----   --------              ---------------- ----\n"
    );

    foreach my $trap ( listNodes( "v3", "trap-target", "tagnode" ) ) {
        my $auth = returnValue( "v3 trap-target $trap auth",    "type" );
        my $priv = returnValue( "v3 trap-target $trap privacy", "type" );
        my $type = returnValue( "v3 trap-target $trap",         "type" );
        my $port = returnValue( "v3 trap-target $trap",         "port" );
        my $user = returnValue( "v3 trap-target $trap",         "user" );
        my $protocol = returnValue( "v3 trap-target $trap", "protocol" );
        my $engineid = returnValue( "v3 trap-target $trap", "engineid" );
        my $vrf = returnValue( "v3 trap-target $trap", "routing-instance" );
        $vrf = 'default' unless $vrf;

        if ( length($trap) >= 30 ) {
            printf(
                "%s\n%-30s%-7s%-9s%-5s%-5s%-7s%-22s%-17s%s\n",
                $trap, "",    $port,     $protocol, $auth,
                $priv, $type, $engineid, $vrf,      $user
            );
        }
        else {
            printf(
                "%-30s%-7s%-9s%-5s%-5s%-7s%-22s%-17s%s\n",
                $trap, $port,     $protocol, $auth, $priv,
                $type, $engineid, $vrf,      $user
            );
        }
    }
    print "\n";
}

sub show_all {
    show_user();
    show_group();
    if ($vrf_available) {
        show_routing_instance_trap();
    }
    else {
        show_trap();
    }
}

my $all;
my $group;
my $user;
my $trap;

GetOptions(
    "all!"   => \$all,
    "group!" => \$group,
    "user!"  => \$user,
    "trap!"  => \$trap,
);

show_all()   if ($all);
show_group() if ($group);
show_user()  if ($user);
if ($vrf_available) {
    show_routing_instance_trap() if ($trap);
}
else {
    show_trap() if ($trap);
}
