#!/usr/bin/perl
# CrowdSec Webmin Module - action.cgi

require './crowdsec-lib.pl';
&ReadParse();

my $service = $in{'service'} // '';
my $action  = $in{'action'}  // '';
my $id      = $in{'id'}      // '';

my %ok_svc = ('crowdsec'=>1,'crowdsec-firewall-bouncer'=>1);
my %ok_act = (start=>1, stop=>1, restart=>1,
              delete_decision=>1, add_whitelist=>1, delete_whitelist=>1);

unless ($ok_act{$action}) {
    &redirect("index.cgi?tab=bouncers&err=invalid_action");
    exit 0;
}

# ── Delete decision ───────────────────────────────────────────────────────────
if ($action eq 'delete_decision') {
    $id =~ s/[^0-9]//g;
    if ($id) {
        my $out = `cscli decisions delete --id \Q$id\E 2>&1`;
        my $rc = $? >> 8;
        &redirect("index.cgi?tab=decisions&" . ($rc==0 ? "deleted=1" : "err=" . uri_escape($out)));
    } else {
        &redirect("index.cgi?tab=decisions&err=invalid_id");
    }
    exit 0;
}

# ── Add whitelist entry ───────────────────────────────────────────────────────
# Kept in Webmin's per-module config dir (root-only), not world-readable /tmp
my $WL_DEBUG_FILE = ($module_config_directory || '/etc/webmin/crowdsec') . '/whitelist_debug.txt';
my $ALLOWLIST_NAME = 'webmin-temp-whitelist';

sub run_debug {
    # runs a shell command, returns (output, rc), and appends to @_debug (passed by ref)
    my ($cmd, $dbgref) = @_;
    my $out = `$cmd`;
    $out = '' unless defined $out;
    my $rc = $? >> 8;
    push @$dbgref, "\$ $cmd\n[exit $rc] $out";
    return ($out, $rc);
}

if ($action eq 'add_whitelist') {
    my $ip     = $in{'wl_ip'}              // '';
    my $dur_sel= $in{'wl_duration'}        // '24h';
    my $dur_cus= $in{'wl_custom_duration'} // '';
    my $reason = $in{'wl_reason'}          // 'manual whitelist';
    # Webmin's ReadParse joins repeated fields (ticked checkboxes) with "\0"
    # into ONE string - it never produces an array ref. Split it.
    my @scopes = grep { length } split /\0/, ($in{'wl_scope'} // '');
    unless (@scopes) {
        &redirect("index.cgi?tab=whitelist&wl_err=Nothing+selected+under+Apply+to");
        exit 0;
    }

    # Validate IP/CIDR
    unless ($ip =~ /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/) {
        &redirect("index.cgi?tab=whitelist&wl_err=Invalid+IP+or+CIDR:+$ip");
        exit 0;
    }

    # Resolve duration
    my $duration = ($dur_sel eq 'custom') ? $dur_cus : $dur_sel;
    unless ($duration && $duration =~ /^\d+[smhd](\d+[smhd])*$/) {
        &redirect("index.cgi?tab=whitelist&wl_err=Invalid+duration+format+(use+e.g.+4h+or+2h30m)");
        exit 0;
    }

    my $reason_e = $reason; $reason_e =~ s/[^A-Za-z0-9 _\-\.]//g;
    $reason_e = 'manual whitelist' unless length $reason_e;
    my @errors;
    my @dbg;

    # 1. Delete existing bans if requested (works regardless of mechanism used below)
    if (grep { $_ eq 'delete_existing' } @scopes) {
        run_debug("cscli decisions delete --ip \Q$ip\E 2>&1", \@dbg);
    }

    # 2. Add to whitelist. CrowdSec >=1.6 uses the dedicated "allowlists" subsystem
    #    instead of "decisions add --type whitelist" (which is no longer accepted by
    #    newer cscli builds). Detect which is supported and use the working one.
    if (grep { $_ eq 'crowdsec' } @scopes) {
        my ($help, $help_rc) = run_debug("cscli allowlists --help 2>&1", \@dbg);
        my $has_allowlists = ($help_rc == 0 && $help !~ /unknown command|no such (sub)?command/i);

        if ($has_allowlists) {
            # Ensure the allowlist exists (idempotent - ignore "already exists")
            my ($cout, $crc) = run_debug(
                "cscli allowlists create \Q$ALLOWLIST_NAME\E -d \Qwebmin-managed temporary whitelist\E 2>&1", \@dbg);
            if ($crc != 0 && $cout !~ /already exist/i) {
                push @errors, "Allowlist create: $cout";
            }
            # Add the entry with an expiration
            my ($aout, $arc) = run_debug(
                "cscli allowlists add \Q$ALLOWLIST_NAME\E \Q$ip\E --expiration \Q$duration\E -d \Q$reason_e\E 2>&1", \@dbg);
            if ($arc != 0) {
                push @errors, "Allowlist add: $aout";
            } else {
                # Read it back - only report success if the entry is really there
                my ($iout) = run_debug("cscli allowlists inspect \Q$ALLOWLIST_NAME\E -o json 2>&1", \@dbg);
                my $idata = load_json($iout);
                my $found = 0;
                if (ref $idata eq 'HASH' && ref $idata->{items} eq 'ARRAY') {
                    $found = grep { ($_->{value} // '') eq $ip } @{$idata->{items}};
                }
                push @errors, "Allowlist add reported OK but $ip is not in the allowlist" unless $found;
            }
        } else {
            # Fallback for older cscli that only supports decision-based whitelisting
            my $scope = ($ip =~ /\//) ? 'Range' : 'Ip';
            my ($out, $rc) = run_debug(
                "cscli decisions add --ip \Q$ip\E --duration \Q$duration\E --type whitelist --scope \Q$scope\E --reason \Q$reason_e\E 2>&1", \@dbg);
            push @errors, "Engine: $out" if $rc != 0;
        }
    }

    # Save the debug transcript so the Whitelist tab can show exactly what ran
    my $old_umask = umask(077);
    if (open(my $fh, '>', $WL_DEBUG_FILE)) {
        print $fh join("\n\n", @dbg);
        close $fh;
        chmod 0600, $WL_DEBUG_FILE;
    }
    umask($old_umask);

    if (@errors) {
        my $err = join(' | ', @errors);
        $err =~ s/[^A-Za-z0-9 _\-\.\:\/\[\]]/+/g;
        &redirect("index.cgi?tab=whitelist&wl_err=$err");
    } else {
        &redirect("index.cgi?tab=whitelist&wl_added=1");
    }
    exit 0;
}

# ── Remove whitelist entry ────────────────────────────────────────────────────
if ($action eq 'delete_whitelist') {
    my $ip = $in{'ip'} // '';
    $id =~ s/[^0-9]//g;
    my @dbg;

    my $rc_total = 0;
    if ($id) {
        my (undef, $rc) = run_debug("cscli decisions delete --id \Q$id\E 2>&1", \@dbg);
        $rc_total ||= $rc;
    }
    if ($ip =~ /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/) {
        run_debug("cscli decisions delete --ip \Q$ip\E --type whitelist 2>&1", \@dbg);
        run_debug("cscli allowlists remove \Q$ALLOWLIST_NAME\E \Q$ip\E 2>&1", \@dbg);
    }

    my $old_umask = umask(077);
    if (open(my $fh, '>', $WL_DEBUG_FILE)) {
        print $fh join("\n\n", @dbg);
        close $fh;
        chmod 0600, $WL_DEBUG_FILE;
    }
    umask($old_umask);

    &redirect("index.cgi?tab=whitelist&wl_deleted=1");
    exit 0;
}

# ── Service start/stop/restart ────────────────────────────────────────────────
unless ($ok_svc{$service}) {
    &redirect("index.cgi?tab=bouncers&err=invalid_service");
    exit 0;
}

my $out = `systemctl \Q$action\E \Q$service\E 2>&1`;
my $rc  = $? >> 8;

if ($rc == 0) {
    &redirect("index.cgi?tab=bouncers&ok=1");
} else {
    &ui_print_header(undef, 'Action Failed', '');
    print <<HTML;
<div style="background:#161b27;color:#e6edf3;font-family:Inter,sans-serif;
  padding:32px;max-width:700px;margin:40px auto;border-radius:10px;border:1px solid #2a3450">
  <h2 style="color:#ff5c5c;margin-bottom:12px">⚠ Failed: $action $service</h2>
  <pre style="background:#0d1117;padding:14px;border-radius:8px;border:1px solid #ff5c5c;
    color:#ff9090;font-size:12px;line-height:1.7;white-space:pre-wrap">$out</pre>
  <a href="index.cgi?tab=bouncers" style="display:inline-block;margin-top:16px;
    background:rgba(108,99,255,.15);color:#a99cff;border:1px solid rgba(108,99,255,.3);
    padding:7px 16px;border-radius:7px;text-decoration:none;font-size:13px">← Back</a>
</div>
HTML
    &ui_print_footer("index.cgi", "Dashboard");
}

sub uri_escape {
    my ($s) = @_;
    $s =~ s/([^A-Za-z0-9\-_.~])/sprintf("%%%02X", ord($1))/ge;
    return $s;
}
