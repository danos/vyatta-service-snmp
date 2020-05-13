# Module: MIBMisc.pm
#
# Copyright (c) 2019-2020, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

package Vyatta::MIBMisc;
use strict;
use warnings;

use SNMP;
use NetSNMP::OID (':all');

use base qw( Exporter );
our @EXPORT =
  qw(create_mib_tree clear_mib_trees sort_mib_keys add_mib_entry get_oid get_next_oid set_oid);

# Sub-agent MIB data tree
#
# Implemented as a hash of registered OIDs each mapping to a hash of child OIDs,
# representing instantiated objects, mapping to an array of (<type>, <value>).
#
# eg. assuming the sub-agent registered to handle OID trees .1.2 and .1.3
#
#   {
#      ".1.2" => {
#                   ".1.2.1.2" => (ASN_OCTET_STR, "foo"),
#                   ".1.2.1.1" => (ASN_INTEGER, 1),
#                },
#      ".1.3" => {
#                   ".1.3.1.10" => (ASN_OCTET_STR, "bar"),
#                   ".1.3.1.11" => (ASN_INTEGER, 20),
#                },
#   }
#
# The child hash for each registered OID is initialised by a call to
# create_mib_tree().
#
# An instantiated object is inserted into the data tree by a call to
# add_mib_entry().
my $mib_tree        = {};

# Sub-agent sorted MIB OIDs
#
# Implemented as a hash of registered OIDs each mapping to a sorted array
# of their child OIDs, used to support GETNEXT operations. This is required
# since the MIB data tree hash is inherently unsorted.
#
# eg. assuming the sub-agent registered to handle OID trees .1.2 and .1.3
#
#   {
#      ".1.2" => ( ".1.2.1.1", ".1.2.1.2" ),
#      ".1.3" => ( ".1.3.1.10", ".1.3.1.11" ),
#   }
#
# Each array is only populated by a call to sort_mib_keys().
my $sorted_mib_tree = {};

sub by_oid ($$) {
    my ( undef, @a ) = split /\./, $_[0];
    my ( undef, @b ) = split /\./, $_[1];
    my $v = 0;
    $v ||= $a[$_] <=> $b[$_] for 0 .. $#a;
    return $v;
}

sub create_mib_tree {
    my ($oid) = @_;

    $mib_tree->{$oid}        = {};
    $sorted_mib_tree->{$oid} = ();
}

sub clear_mib_trees {
    foreach my $key ( keys %{$mib_tree} ) {
        $mib_tree->{$key} = {};
    }

    foreach my $key ( keys %{$sorted_mib_tree} ) {
        $sorted_mib_tree->{$key} = ();
    }
}

sub sort_mib_keys {
    my ($oid) = @_;

    my $tree        = $mib_tree->{$oid};
    my @sorted_oids = sort by_oid keys %{$tree};
    $sorted_mib_tree->{$oid} = \@sorted_oids;
}

sub add_mib_entry {
    my ( $oid, $entry_oid, $type, $value ) = @_;

    return
      if ( !defined($oid)
        || !defined($entry_oid)
        || !defined($type)
        || !defined($value) );
    my @args = ( $type, $value );
    my $tree = $mib_tree->{$oid};
    $tree->{$entry_oid} = \@args;
}

sub get_reg_oid {
    my ($oid) = @_;

    my $noid = $oid;
    if ( $oid !~ /^[\.0-9]+$/ ) {
        $noid = SNMP::translateObj($oid);
    }
    foreach my $key ( keys %{$mib_tree} ) {
        return $key if ( $noid =~ m/$key/ );
    }
}

sub get_oid {
    my ($oid) = @_;

    my $noid        = SNMP::translateObj($oid);
    my $reg_oid     = get_reg_oid($oid);
    my $sorted_tree = $sorted_mib_tree->{$reg_oid};
    my $tree        = $mib_tree->{$reg_oid};
    if ( $tree->{$noid} ) {
        my ( $type, $value ) = @{ $tree->{$noid} };
        return ( $type, $value );
    }
}

sub get_next_oid {
    my ($oid) = @_;

    my $reg_oid     = get_reg_oid($oid);
    my $sorted_tree = $sorted_mib_tree->{$reg_oid};
    my $count       = $#$sorted_tree;
    my $index       = 0;
    my $curr_oid;
    while ( $index <= $count ) {
        $curr_oid = $sorted_tree->[$index];
        my $curr_noid = new NetSNMP::OID($curr_oid);
        last if ( snmp_oid_compare( $oid, $curr_noid ) < 0 );
        $index++;
    }
    if ( $index <= $count ) {
        my $tree = $mib_tree->{$reg_oid};
        if ( $tree->{$curr_oid} ) {
            my ( $type, $value ) = @{ $tree->{$curr_oid} };
            return ( $curr_oid, $type, $value );
        }
    }
}

sub set_oid {
    my ( $base, $oid ) = @_;

    return if ( !defined($base) || !defined($oid) );
    return $base if ( $oid eq "" );
    return "$base.$oid";
}

1;
