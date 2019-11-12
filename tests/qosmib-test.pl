#!/usr/bin/perl
#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
use strict;
use warnings;
use Readonly;
use File::Basename;

use Data::Dumper;

use Test::More tests => 22;

Readonly my $VQMOID   => ".1.3.6.1.4.1.74.1.32";
Readonly my $VQM      => "vyattaqosmib.pl";
Readonly my $VQMSTATS => "qosmib-stats.json";

Readonly my @expected_oids => (
    {
        'oid'         => '1.1.1.1.2.101.0.0',
        'regex-type'  => 'S+',
        'regex-value' => 'd+',
        'type'        => 'integer',
        'value'       => 101
    },
    {
        'oid'         => '1.1.1.1.2.102.0.0',
        'regex-type'  => 'S+',
        'regex-value' => 'd+',
        'type'        => 'integer',
        'value'       => 102
    },
    {
        'oid'         => '1.1.1.1.2.101.1010.0',
        'regex-type'  => 'S+',
        'regex-value' => 'd+',
        'type'        => 'integer',
        'value'       => 101
    },
    {
        'oid'         => '1.1.1.1.3.101.2010.0',
        'regex-type'  => 'S+',
        'regex-value' => 'S+',
        'type'        => 'string',
        'value'       => 'default-prof'
    },
    {
        'oid'         => '1.1.1.1.3.101.2010.1',
        'regex-type'  => 'S+',
        'regex-value' => 'S+',
        'type'        => 'string',
        'value'       => 'vlan-profile-50M'
    },
    {
        'oid'         => '1.1.1.1.4.101.2010.1',
        'regex-type'  => 'S+',
        'regex-value' => 'd+',
        'type'        => 'integer',
        'value'       => 2010
    },
    {
        'oid'         => '1.3.1.1.4.101.1010.2',
        'regex-type'  => 'S+',
        'regex-value' => 'd+',
        'type'        => 'counter64',
        'value'       => 6512386
    },
);

sub get_cmd_out {
    my ($cmd) = @_;
    open my $cmdout, q{-|}, "$cmd"
      or return;
    my $output;
    while (<$cmdout>) {
        $output .= $_;
    }
    close $cmdout
      or return;
    return $output;
}

my $vqmscript = "../scripts/snmp/$VQM";

ok( -X $vqmscript, "QOS MIB script exists?" );

my $cmdout = get_cmd_out("$vqmscript --statsfile $VQMSTATS --idle 1 --interval 1");

foreach my $oid (@expected_oids) {

    #    print "OID: \n" . Dumper($oid);
    my $matchexpr = sprintf( "%s.%s \\s+ \\((\\%s)\\) \\s+ = \\s+ (\\%s)",
        $VQMOID, $oid->{oid}, $oid->{'regex-type'}, $oid->{'regex-value'} );

    #    print "MATCH: $matchexpr\n";
    my $tc = "Checking OID " . $oid->{oid};
    ok( $cmdout =~ m/$matchexpr/msx, $tc . " found?" );
    is( $1, $oid->{type},  $tc . " type is as expected?" );
    is( $2, $oid->{value}, $tc . " value is as expected?" );
}

done_testing();
exit 0;
