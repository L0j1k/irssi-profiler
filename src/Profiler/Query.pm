package Profiler::Query;

use strict;
use warnings;

# Parses a /profiler query expression into terms and a page number.
#
#   <field> <pattern> [ (&& | ||) <field> <pattern> ]... [page]
#
# Patterns are globs, turned into a LIKE by Profiler::Store. A pattern may be
# single- or double-quoted to hold spaces or a literal && or ||; unquoted, it
# runs to the next operator or the end. Operators need a space on each side. A
# bare number after the last pattern is the page. && is AND, || is OR; the
# store leaves their precedence to SQLite, where AND binds tighter than OR.

# Splits an expression on top-level " && " / " || ", leaving operators inside
# quotes alone. Returns (chunk, op, chunk, op, ..., chunk) with ops as 'AND' or
# 'OR'. A single term comes back as one chunk.
sub split_on_bool {
    my ($expr) = @_;
    my @out;
    my $buf = '';
    my $quote = '';
    for (my $i = 0; $i < length $expr; $i++) {
        my $ch = substr($expr, $i, 1);
        if ($quote) {
            $buf .= $ch;
            $quote = '' if $ch eq $quote;
            next;
        }
        if ($ch eq "'" || $ch eq '"') {
            $quote = $ch;
            $buf .= $ch;
            next;
        }
        if (substr($expr, $i) =~ /^(\s+)(&&|\|\|)(?=\s|$)/) {
            push @out, $buf, ($2 eq '||' ? 'OR' : 'AND');
            $buf = '';
            $i += length($1) + length($2) - 1;
            next;
        }
        $buf .= $ch;
    }
    push @out, $buf;
    return @out;
}

# Returns (\@terms, $page), or () when the expression is malformed (a term
# without a pattern). Each term is { field, pattern } plus op => 'AND' or 'OR'
# on every term after the first. Fields are lowercased; the store checks they
# are searchable.
sub parse {
    my ($expr) = @_;
    my @chunks = split_on_bool($expr);
    my (@terms, $page);
    for (my $i = 0; $i < @chunks; $i += 2) {
        my $op = $i == 0 ? undef : $chunks[$i - 1];
        my ($field, $rest) = $chunks[$i] =~ /^\s*(\S+)\s+(.*\S)\s*$/;
        return () unless defined $rest;
        # The page is a bare number after the last pattern only, so a quoted
        # pattern that ends in a number keeps it.
        my $pattern;
        my $last = $i + 1 >= @chunks;
        if ($last && $rest =~ /^(['"])(.*)\1(?:\s+(\d+))?\s*$/) { ($pattern, $page) = ($2, $3); }
        elsif ($last && $rest =~ /^(.*\S)\s+(\d+)\s*$/)         { ($pattern, $page) = ($1, $2); }
        else { ($pattern = $rest) =~ s/^(['"])(.*)\1$/$2/; }
        push @terms, { field => lc $field, pattern => $pattern, ($op ? (op => $op) : ()) };
    }
    return () unless @terms;
    $page = 1 if !$page || $page < 1;
    return (\@terms, $page);
}

# The terms written back out for a result header, like
# "version matches '*HexChat*' && nick matches '*bob*'".
sub describe {
    my ($terms) = @_;
    return join ' ', map {
        ($_->{op} ? (($_->{op} eq 'OR' ? '||' : '&&') . ' ') : '') . "$_->{field} matches '$_->{pattern}'"
    } @$terms;
}

1;
