#!/usr/bin/perl
# CrowdSec Webmin Module - action.cgi

require './crowdsec-lib.pl';
&ReadParse();

my $service = $in{'service'} // '';
my $action  = $in{'action'}  // '';
my $id      = $in{'id'}      // '';

my %ok_svc = ('crowdsec'=>1,'crowdsec-firewall-bouncer'=>1);
my %ok_act = (start=>1,stop=>1,restart=>1,delete_decision=>1);

unless ($ok_act{$action}) {
    &redirect("index.cgi?tab=services&err=invalid_action");
    exit 0;
}

if ($action eq 'delete_decision') {
    $id =~ s/[^0-9]//g;  # numeric only
    # Preserve whatever filter the decisions view was showing when the
    # delete was triggered, so the redirect lands back on the same filtered
    # list instead of resetting to the unfiltered default.
    my @filter_keys = qw(ip range scope value scenario type origin since until);
    my $qs = join('&', map { defined $in{$_} && $in{$_} ne '' ? "$_=" . uri_escape($in{$_}) : () } @filter_keys);
    $qs = "&$qs" if $qs;
    if ($id) {
        my ($ok, $err) = delete_decision_by_id($id);
        &redirect("index.cgi?tab=decisions" . $qs . '&' . ($ok ? "deleted=1" : "err=" . uri_escape($err // 'delete failed')));
    } else {
        &redirect("index.cgi?tab=decisions" . $qs . "&err=invalid_id");
    }
    exit 0;
}

unless ($ok_svc{$service}) {
    &redirect("index.cgi?tab=services&err=invalid_service");
    exit 0;
}

my $out = `systemctl \Q$action\E \Q$service\E 2>&1`;
my $rc  = $? >> 8;

if ($rc == 0) {
    &redirect("index.cgi?tab=services&ok=1");
} else {
    &ui_print_header(undef, 'Action Failed', '');
    print <<HTML;
<div style="background:#161b27;color:#e6edf3;font-family:Inter,sans-serif;
  padding:32px;max-width:700px;margin:40px auto;border-radius:10px;border:1px solid #2a3450">
  <h2 style="color:#ff5c5c;margin-bottom:12px">⚠ Failed: $action $service</h2>
  <pre style="background:#0d1117;padding:14px;border-radius:8px;border:1px solid #ff5c5c;
    color:#ff9090;font-size:12px;line-height:1.7;white-space:pre-wrap">$out</pre>
  <a href="index.cgi?tab=services" style="display:inline-block;margin-top:16px;
    background:rgba(108,99,255,.15);color:#a99cff;border:1px solid rgba(108,99,255,.3);
    padding:7px 16px;border-radius:7px;text-decoration:none;font-size:13px">← Back</a>
</div>
HTML
    &ui_print_footer("index.cgi", "Dashboard");
}
