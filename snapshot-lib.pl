#!/usr/bin/perl
# CrowdSec Webmin Module - snapshot-lib.pl
#
# Pure-Perl helpers (no Webmin libraries) shared by index.cgi and the hourly
# cron script snapshot.pl. The firewall bouncer only reports running totals
# since it last started, so we save a timestamped copy of those counters
# regularly and compute "this week" / "last week" from the differences.
#
# History file format: one JSON object per line
#   {"ts":1760270400,"o":{"CAPI":{"p":372044,"b":20587682},"crowdsec":{...},"":{"p":...}}}
# Origin "" holds total processed traffic; the others hold dropped traffic.

use strict;
use warnings;

my $HISTORY_KEEP_DAYS = 60;

sub snap_json_decode {
    my ($txt) = @_;
    return undef unless defined $txt && $txt =~ /^\s*[\[\{]/;
    require JSON::PP;
    return eval { JSON::PP::decode_json($txt) };
}

sub snap_json_encode {
    require JSON::PP;
    return JSON::PP->new->canonical->encode($_[0]);
}

# Read the bouncer counters right now: { origin => {p=>packets, b=>bytes} }
sub snap_read_counters {
    my $json = `cscli metrics show bouncers -o json 2>/dev/null`;
    my $data = snap_json_decode($json);
    return undef unless ref $data eq 'HASH' && ref $data->{bouncers} eq 'HASH';
    my %o;
    for my $bname (keys %{$data->{bouncers}}) {
        my $b = $data->{bouncers}{$bname};
        next unless ref $b eq 'HASH';
        for my $origin (keys %$b) {
            my $od = $b->{$origin};
            next unless ref $od eq 'HASH';
            my $src = $origin eq '' ? $od->{processed} : $od->{dropped};
            next unless ref $src eq 'HASH';
            $o{$origin}{p} += $src->{packet} || 0;
            $o{$origin}{b} += $src->{byte}   || 0;
        }
    }
    return \%o;
}

sub snap_load {
    my ($file) = @_;
    my @rows;
    open(my $fh, '<', $file) or return [];
    while (my $l = <$fh>) {
        my $r = snap_json_decode($l);
        push @rows, $r if ref $r eq 'HASH' && $r->{ts} && ref $r->{o} eq 'HASH';
    }
    close $fh;
    @rows = sort { $a->{ts} <=> $b->{ts} } @rows;
    return \@rows;
}

# Append a snapshot unless the last one is younger than $min_gap seconds.
# Returns 1 if a snapshot was written.
sub snap_take {
    my ($file, $min_gap) = @_;
    $min_gap //= 0;
    my $rows = snap_load($file);
    my $now  = time();
    return 0 if @$rows && $now - $rows->[-1]{ts} < $min_gap;
    my $o = snap_read_counters() or return 0;

    my $old_umask = umask(077);
    my $cutoff = $now - $HISTORY_KEEP_DAYS * 86400;
    if (@$rows && $rows->[0]{ts} < $cutoff) {
        # prune: rewrite without the oldest rows
        open(my $fh, '>', "$file.tmp") or do { umask($old_umask); return 0 };
        print $fh snap_json_encode($_), "\n" for grep { $_->{ts} >= $cutoff } @$rows;
        close $fh;
        rename("$file.tmp", $file);
    }
    open(my $fh, '>>', $file) or do { umask($old_umask); return 0 };
    print $fh snap_json_encode({ ts => $now, o => $o }), "\n";
    close $fh;
    umask($old_umask);
    return 1;
}

# Traffic counted between $from and $to (epoch secs), per origin.
# Handles bouncer restarts (counter going backwards = restarted from 0).
# Returns ({origin=>{p,b}}, $covered_seconds) - covered < window means
# there isn't enough history yet to cover the whole period.
sub snap_delta {
    my ($rows, $from, $to) = @_;
    my (%sum, $first, $last);
    my $prev;
    for my $r (@$rows) {
        if ($r->{ts} <= $from) { $prev = $r; next; }   # baseline: last snapshot before window
        last if $r->{ts} > $to;
        if ($prev) {
            $first //= $prev->{ts};
            for my $origin (keys %{$r->{o}}) {
                for my $k (qw(p b)) {
                    my $cur = $r->{o}{$origin}{$k} || 0;
                    my $old = ($prev->{o}{$origin} || {})->{$k} || 0;
                    $sum{$origin}{$k} += $cur >= $old ? $cur - $old : $cur;
                }
            }
            $last = $r->{ts};
        }
        $prev = $r;
    }
    my $covered = ($first && $last) ? $last - $first : 0;
    return (\%sum, $covered);
}

1;
