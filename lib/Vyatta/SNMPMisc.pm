# Module: SNMPMisc.pm
#
# Copyright (c) 2021, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

package Vyatta::SNMPMisc;
use strict;
use warnings;

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Configd;

use base qw( Exporter );
our @EXPORT = qw(listNodes returnValue returnValues isExists);

my $configd = Vyatta::Configd::Client->new();
my $db      = $Vyatta::Configd::Client::AUTO;
my $snmp    = "service snmp";

sub listNodes {
    my ( $path, $node, $key ) = @_;
    return unless $configd->node_exists( $db, "$snmp $path $node" );
    my $val = $configd->tree_get_hash("$snmp $path $node")->{$node};
    return map( $_->{$key}, @$val );
}

sub returnValue {
    my ( $path, $node ) = @_;
    return "" unless $configd->node_exists( $db, "$snmp $path $node" );
    return $configd->tree_get_hash("$snmp $path $node")->{$node};
}

sub returnValues {
    my ( $path, $node ) = @_;
    return unless $configd->node_exists( $db, "$snmp $path $node" );
    return @{ $configd->tree_get_hash("$snmp $path $node")->{$node} };
}

sub isExists {
    my ($path) = @_;
    return 1 if $configd->node_exists( $db, "$snmp $path" );
    return 0;
}

1;
