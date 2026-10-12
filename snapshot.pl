#!/usr/bin/perl
# CrowdSec Webmin Module - snapshot.pl
# Run hourly from cron (enabled from the Weekly Report tab). Saves the
# firewall bouncer's counters so weekly totals and trends can be computed.
#   usage: snapshot.pl /etc/webmin/crowdsec/history.jsonl

use strict;
use warnings;
use FindBin;
require "$FindBin::Bin/snapshot-lib.pl";

my $file = shift @ARGV or die "usage: $0 <history-file>\n";
$ENV{PATH} = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
snap_take($file, 300);   # skip if one was taken in the last 5 minutes
exit 0;
