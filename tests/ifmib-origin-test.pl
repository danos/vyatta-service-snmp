#! /usr/bin/perl

# Standalone test for Vyatta::IFMib, not intended to be used
# directly
#
# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
use strict;
use warnings;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Misc;
use Vyatta::IFMib
  qw(%mib ifmib_get ifmib_get_next ifmib_get_intf_hash get_octets);
use Test::More tests => 75;

# OID of ipAddressOrigin [RFC4293]
my $BASE = '.1.3.6.1.2.1.4.34.1.6';

my %config_v4_addrs = (
    '127.0.0.1' => {
        'ifname'    => 'lo',
        'ut_expect' => {
            'get_oid'   => '.1.3.6.1.2.1.4.34.1.6.1.4.127.0.0.1',
            'get_next'  => '169.254.0.2',
            'oid_value' => '1',
        },
    },
    '192.168.122.14' => {
        'ifname'    => 'dp0s3',
        'ut_expect' => {
            'get_oid'   => '.1.3.6.1.2.1.4.34.1.6.1.4.192.168.122.14',
            'get_next'  => '192.168.122.255',
            'oid_value' => '4',
        },
    },
    '192.168.122.255' => {
        'ifname'    => 'dp0s3',
        'ut_expect' => {
            'get_oid'   => '.1.3.6.1.2.1.4.34.1.6.1.4.192.168.122.255',
            'oid_value' => '4',
        },
    },
    '10.0.0.10' => {
        'ifname'    => 'dp0s4',
        'ut_expect' => {
            'get_oid'   => '.1.3.6.1.2.1.4.34.1.6.1.4.10.0.0.10',
            'get_next'  => '10.0.0.255',
            'oid_value' => '2',
        },
    },
    '10.0.0.255' => {
        'ifname'    => 'dp0s4',
        'ut_expect' => {
            'get_oid'   => '.1.3.6.1.2.1.4.34.1.6.1.4.10.0.0.255',
            'get_next'  => '127.0.0.1',
            'oid_value' => '2',
        },
    },
    '169.254.0.2' => {
        'ifname'    => 'dp0s6',
        'ut_expect' => {
            'get_oid'   => '.1.3.6.1.2.1.4.34.1.6.1.4.169.254.0.2',
            'get_next'  => '169.254.255.255',
            'oid_value' => '6',
        },
    },
    '169.254.255.255' => {
        'ifname'    => 'dp0s6',
        'ut_expect' => {
            'get_oid'   => '.1.3.6.1.2.1.4.34.1.6.1.4.169.254.255.255',
            'get_next'  => '192.168.122.14',
            'oid_value' => '6',
        },
    },
);

my %config_v6_addrs = (
    '0000:0000:0000:0000:0000:0000:0000:0001' => {
        'addr'      => '::1',
        'ifname'    => 'lo',
        'ut_expect' => {
            'get_oid' =>
              '.1.3.6.1.2.1.4.34.1.6.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1',
            'get_next'  => '0020:0000:0000:0000:0000:0001:0000:0050',
            'oid_value' => '1',
        },
    },
    '0020:0000:0000:0000:0000:0001:0000:0050' => {
        'addr'      => '20::1:0:50',
        'ifname'    => 'dp0s5',
        'ut_expect' => {
            'get_oid' =>
              '.1.3.6.1.2.1.4.34.1.6.2.16.0.32.0.0.0.0.0.0.0.0.0.1.0.0.0.80',
            'get_next'  => 'cafe:0000:0000:0000:0000:0000:0000:0002',
            'oid_value' => '4',
        },
    },
    'cafe:0000:0000:0000:0000:0000:0000:0002' => {
        'addr'      => 'cafe::2',
        'ifname'    => 'dp0s6',
        'ut_expect' => {
            'get_oid' =>
              '.1.3.6.1.2.1.4.34.1.6.2.16.202.254.0.0.0.0.0.0.0.0.0.0.0.0.0.2',
            'get_next' => 'fe80:0000:0000:0000:5054:00ff:fe00:0cf3',

            'oid_value' => '2',
        },
    },
    'fe80:0000:0000:0000:5054:00ff:fe00:0cf3' => {
        'addr'      => 'fe80::5054:ff:fe00:cf3',
        'ifname'    => 'dp0s3',
        'ut_expect' => {
            'get_oid' =>
'.1.3.6.1.2.1.4.34.1.6.2.16.254.128.0.0.0.0.0.0.80.84.0.255.254.0.12.243',
            'oid_value' => '5',
        },
    },
);

my $ip_addr_show_str = <<'EOSTR';
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
6: .spathintf: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    link/none 
7: dp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 500
    link/ether 52:54:00:00:0c:f3 brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.14/24 brd 192.168.122.255 scope global dp0s3
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:fe00:cf3/64 scope link 
       valid_lft forever preferred_lft forever
8: dp0s4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 500
    link/ether 52:54:00:b8:79:1b brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.10/24 brd 10.0.0.255 scope global dp0s4
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:feb8:791b/64 scope link 
       valid_lft forever preferred_lft forever
9: dp0s5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 500
    link/ether 52:54:00:28:48:9b brd ff:ff:ff:ff:ff:ff
    inet6 20::1:0:50/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:fe28:489b/64 scope link 
       valid_lft forever preferred_lft forever
10: dp0s6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 500
    link/ether 52:54:00:e3:48:f6 brd ff:ff:ff:ff:ff:ff
    inet 169.254.0.2/16 brd 169.254.255.255 scope global dp0s6
       valid_lft forever preferred_lft forever
    inet6 cafe::2/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:fee3:48f6/64 scope link 
       valid_lft forever preferred_lft forever
EOSTR

sub get_type_v4 {
    my ( $key, $ip, $ifname ) = @_;

    my $type = $config_v4_addrs{$key}{ut_expect}{oid_value};

    return $type;
}

sub get_type_v6 {
    my ( $key, $ipv6, $ifname ) = @_;

    my $type = $config_v6_addrs{$key}{ut_expect}{oid_value};

    return $type;
}

my $key;
my %ihash = %config_v4_addrs;

foreach $key ( sort ( keys %ihash ) ) {
    my $ref = \%ihash;
    my $ip  = new NetAddr::IP $key;
    next unless defined($ip);

    my $tc = "get oid check address=" . $key;
    local *Vyatta::IFMib::ifmib_get_intf_hash =
      sub { return \%config_v4_addrs; };
    my ( $oid_type, $oid_value ) =
      ifmib_get( $mib{IPV4_ADDR}, $mib{IPV4_ADDRLEN}, $key, \&get_type_v4 );
    is( $oid_type, 'integer', $tc . " type 'integer' check" );
    my $exp_value = $config_v4_addrs{$key}{ut_expect}{oid_value};
    is( $exp_value, $oid_value, $tc . " oid value check" );
    pass($tc);
}

foreach $key ( sort ( keys %ihash ) ) {
    my $ref = \%ihash;
    my $ip  = new NetAddr::IP $key;
    next unless defined($ip);

    my $tc = "get next oid check address=" . $key;
    local *Vyatta::IFMib::ifmib_get_intf_hash =
      sub { return \%config_v4_addrs; };
    my ( $next_oid, $oid_type, $oid_value ) =
      ifmib_get_next( $BASE, $mib{IPV4_ADDR}, $mib{IPV4_ADDRLEN}, $key,
        \&get_type_v4 );
    next unless defined($next_oid);
    my $get_next = $config_v4_addrs{$key}{ut_expect}{get_next};
    next unless defined($get_next);

    is( $oid_type, 'integer', $tc . " type 'integer' check" );
    my $exp_next_oid = $config_v4_addrs{$get_next}{ut_expect}{get_oid};
    is( $exp_next_oid, $next_oid, $tc . " next oid check" );
    pass($tc);
}

%ihash = %config_v6_addrs;
foreach $key ( sort ( keys %ihash ) ) {
    my $ref  = \%ihash;
    my $ipv6 = new NetAddr::IP $key;

    my $addr = $config_v6_addrs{$key}{addr};
    my $tc   = "get oid check address=" . $addr;
    local *Vyatta::IFMib::ifmib_get_intf_hash =
      sub { return \%config_v6_addrs; };
    my $exp_value = $config_v6_addrs{$key}{ut_expect}{oid_value};
    my $oct       = get_octets($key);
    my ( $oid_type, $oid_value ) =
      ifmib_get( $mib{IPV6_ADDR}, $mib{IPV6_ADDRLEN}, $oct, \&get_type_v6 );
    is( $oid_type,  'integer',  $tc . " type 'integer' check" );
    is( $exp_value, $oid_value, $tc . " oid value check" );
    pass($tc);
}

foreach $key ( sort ( keys %ihash ) ) {
    my $ref  = \%ihash;
    my $addr = $config_v6_addrs{$key}{addr};
    my $ipv6 = new NetAddr::IP $addr;

    my $tc = "next oid check address=" . $addr;
    local *Vyatta::IFMib::ifmib_get_intf_hash =
      sub { return \%config_v6_addrs; };
    my $oct = get_octets($key);
    my ( $next_oid, $oid_type, $oid_value ) =
      ifmib_get_next( $BASE, $mib{IPV6_ADDR}, $mib{IPV6_ADDRLEN}, $oct,
        \&get_type_v6 );

    my $get_next = $config_v6_addrs{$key}{ut_expect}{get_next};
    next unless defined($get_next);

    is( $oid_type, 'integer', $tc . " type 'integer' check" );
    my $exp_next_oid = $config_v6_addrs{$get_next}{ut_expect}{get_oid};
    is( $exp_next_oid, $next_oid, $tc . " next oid check" );
    pass($tc);
}

my $tref;
my %thash;
%ihash = %config_v4_addrs;
$tref  = ifmib_get_intf_hash("inet");
%thash = %{$tref};
foreach $key ( sort ( keys %ihash ) ) {
    local *IPC::System::Simple::capture = sub { return \$ip_addr_show_str; };
    my $tc = "hash lookup address=" . $key;
    is( $thash{$key}{ifname}, $ihash{$key}{ifname}, $tc . " ifname" );
}

%ihash = %config_v6_addrs;
$tref  = ifmib_get_intf_hash("inet6");
%thash = %{$tref};
foreach $key ( sort ( keys %ihash ) ) {
    local *IPC::System::Simple::capture = sub { return \$ip_addr_show_str; };
    my $addr = $config_v6_addrs{$key}{addr};
    my $tc   = "hash lookup address=" . $addr;
    is( $thash{$key}{ifname}, $ihash{$key}{ifname}, $tc . " ifname" );
    is( $thash{$key}{addr}, $ihash{$key}{addr}, $tc . " addr" );
}

done_testing();

exit 0;
