#!/usr/bin/perl
# CrowdSec Webmin Module - crowdsec-lib.pl

require '../web-lib.pl';
&init_config();
require '../ui-lib.pl';

our %text;
&load_language('crowdsec');

# ── JSON loader ───────────────────────────────────────────────────────────────
# ── JSON loader ───────────────────────────────────────────────────────────────
sub load_json {
    my ($json) = @_;
    return undef unless defined $json && $json =~ /^\s*[\[\{]/;
    # Prefer JSON.pm (faster) but fall back to JSON::PP (core, always
    # available). Resolve a real code ref rather than relying on import(),
    # so this works correctly regardless of which one is actually present.
    my $decoder;
    eval { require JSON; $decoder = \&JSON::decode_json; 1 }
        or eval { require JSON::PP; $decoder = \&JSON::PP::decode_json; 1 };
    return undef unless $decoder;
    my $data = eval { $decoder->($json) };
    return $data;
}

# ── Safe cscli execution ──────────────────────────────────────────────────────
# Runs cscli with an argv list via list-form open() - this execs the binary
# directly, bypassing the shell entirely, so filter values (which now come
# from URL query params driving the alerts/decisions tabs) can never be
# used for command injection no matter what characters they contain.
sub run_cscli_json {
    my (@args) = @_;
    my @cmd = ('cscli', @args, '-o', 'json');
    my $pid = open(my $fh, '-|');
    return undef unless defined $pid;
    if ($pid == 0) {
        open(STDIN,  '<', '/dev/null');
        open(STDERR, '>', '/dev/null');
        exec(@cmd) or exit(127);
    }
    local $/;
    my $out = <$fh>;
    close $fh;
    return $out;
}

# Builds a safe argv fragment from a filter hashref, translating only known
# keys to their cscli flag. Unknown keys are silently ignored, so a filter
# hash built straight from %in can never inject an arbitrary flag.
sub _filter_args {
    my ($filters, $map) = @_;
    my @args;
    return @args unless ref $filters eq 'HASH';
    for my $key (sort keys %$map) {
        my $val = $filters->{$key};
        next unless defined $val && $val ne '';
        push @args, $map->{$key}, $val;
    }
    push @args, '--all' if $filters->{all};
    return @args;
}

# ── Service ───────────────────────────────────────────────────────────────────
sub get_service_status {
    my ($svc) = @_;
    my $out = `systemctl is-active \Q$svc\E 2>/dev/null`;
    chomp $out; return $out || 'unknown';
}

sub get_service_errors {
    my ($svc) = @_;
    my $out = `journalctl -u \Q$svc\E -p err -n 20 --no-pager --output=short 2>/dev/null`;
    $out =~ s/^\s+|\s+$//g; return $out || '';
}

# ── Alerts ────────────────────────────────────────────────────────────────────
# get_alerts_detail($since, \%filters) - $since defaults to '24h' as before.
# %filters (all optional): ip, range, scope, scenario, type, origin, until, all.
# Note: cscli alerts list has no flag for filtering by target engine or by AS -
# those are applied as a post-filter in index.cgi after fetching.
my %ALERT_FILTER_MAP = (
    range    => '--range',
    scope    => '--scope',
    scenario => '--scenario',
    type     => '--type',
    origin   => '--origin',
    until    => '--until',
    ip       => '--ip',
);

sub get_alerts_detail {
    my ($since, $filters) = @_;
    $since ||= '24h';
    my @args = ('alerts', 'list', '--since', $since, _filter_args($filters, \%ALERT_FILTER_MAP));
    my $json = run_cscli_json(@args);
    my $data = load_json($json);
    return ref $data eq 'ARRAY' ? $data : [];
}

# Fetch a single alert with its full event/decision detail, for the
# alert-detail drill-down view.
sub get_alert_by_id {
    my ($id) = @_;
    return undef unless defined $id && $id =~ /^\d+$/;
    my $json = run_cscli_json('alerts', 'inspect', $id, '--details');
    return load_json($json);
}

# ── Decisions ─────────────────────────────────────────────────────────────────
# get_decisions(\%filters) - %filters (all optional): ip, range, scope, value,
# scenario, type, origin, since, until, all.
my %DECISION_FILTER_MAP = (
    range    => '--range',
    scope    => '--scope',
    value    => '--value',
    scenario => '--scenario',
    type     => '--type',
    origin   => '--origin',
    since    => '--since',
    until    => '--until',
    ip       => '--ip',
);

sub get_decisions {
    my ($filters) = @_;
    my @args = ('decisions', 'list', _filter_args($filters, \%DECISION_FILTER_MAP));
    my $json = run_cscli_json(@args);
    my $data = load_json($json);
    if (ref $data eq 'HASH' && ref $data->{rows} eq 'ARRAY') { $data = $data->{rows}; }
    return [] unless ref $data eq 'ARRAY';

    # Known cscli bug (upstream crowdsecurity/crowdsec#4293): on some
    # versions, `cscli decisions list -o json` returns ALERT objects
    # (scenario/source/decisions[]) instead of DECISION objects
    # (origin/scope/value/until). That shape has no top-level "value" but
    # does have an embedded "decisions" array - detect it and flatten, so
    # the Decisions tab still shows real IPs/origins instead of "-".
    if (@$data && ref $data->[0] eq 'HASH' && !exists $data->[0]{value} && ref $data->[0]{decisions} eq 'ARRAY') {
        my @flat;
        for my $alert (@$data) {
            my $src_ip = $alert->{source}{ip};
            for my $d (@{$alert->{decisions} || []}) {
                push @flat, {
                    id       => $d->{id},
                    value    => $d->{value} // $src_ip,
                    type     => $d->{type},
                    scope    => $d->{scope},
                    origin   => $d->{origin},
                    scenario => $d->{scenario} // $alert->{scenario},
                    duration => $d->{duration},
                    alert_id => $alert->{id},
                };
            }
        }
        return \@flat;
    }
    return $data;
}

# Delete a single decision by numeric ID. Moved here from action.cgi so both
# the row-level delete button and any future bulk action share one safe path.
sub delete_decision_by_id {
    my ($id) = @_;
    return (0, 'invalid id') unless defined $id && $id =~ /^\d+$/;
    my $pid = open(my $fh, '-|');
    return (0, "fork failed: $!") unless defined $pid;
    if ($pid == 0) {
        open(STDERR, '>&STDOUT');
        exec('cscli', 'decisions', 'delete', '--id', $id) or exit(127);
    }
    local $/;
    my $out = <$fh>;
    close $fh;
    my $rc = $? >> 8;
    return ($rc == 0 ? 1 : 0, $rc == 0 ? undef : $out);
}

# ── Metrics ───────────────────────────────────────────────────────────────────
sub parse_bouncer_metrics {
    # Try multiple cscli metrics formats across versions
    my $json = `cscli metrics -o json 2>/dev/null`;
    my $data = load_json($json);
    my %totals = (bytes => 0, packets => 0, requests => 0);

    if (ref $data eq 'HASH') {
        # Format 1: {bouncers: {name: {dropped_bytes, dropped_packets}}}
        if (ref $data->{bouncers} eq 'HASH') {
            for my $b (values %{$data->{bouncers}}) {
                $totals{bytes}    += $b->{dropped_bytes}   || $b->{bytes_written}   || 0;
                $totals{packets}  += $b->{dropped_packets} || $b->{packets_written} || 0;
                $totals{requests} += $b->{requests_count}  || $b->{req_processed}   || 0;
            }
        }
        # Format 2: {remediation_components: [...]}
        if (ref $data->{remediation_components} eq 'ARRAY') {
            for my $b (@{$data->{remediation_components}}) {
                $totals{bytes}    += $b->{dropped_bytes}   || 0;
                $totals{packets}  += $b->{dropped_packets} || 0;
                $totals{requests} += $b->{requests_count}  || 0;
            }
        }
    }
    # Format 3: array of bouncer objects
    elsif (ref $data eq 'ARRAY') {
        for my $b (@$data) {
            $totals{bytes}    += $b->{dropped_bytes}   || 0;
            $totals{packets}  += $b->{dropped_packets} || 0;
            $totals{requests} += $b->{requests_count}  || 0;
        }
    }

    # If still zero, try cscli bouncers list which has metrics in some versions
    if ($totals{bytes} == 0 && $totals{packets} == 0) {
        my $bjson = `cscli bouncers list -o json 2>/dev/null`;
        my $bdata = load_json($bjson);
        if (ref $bdata eq 'ARRAY') {
            for my $b (@$bdata) {
                $totals{bytes}    += $b->{dropped_bytes}   || $b->{bytes_dropped}   || 0;
                $totals{packets}  += $b->{dropped_packets} || $b->{packets_dropped} || 0;
            }
        }
    }
    return \%totals;
}

# ── Scenario counts ───────────────────────────────────────────────────────────
sub get_scenario_counts {
    my ($alerts) = @_;
    my %counts;
    for my $a (@$alerts) {
        my $sc = $a->{scenario} // 'unknown';
        $counts{$sc}++;
    }
    return \%counts;
}

# ── Timeline JSON ─────────────────────────────────────────────────────────────
sub get_timeline_json {
    my ($alerts, $field) = @_;
    my %counts;
    for my $a (@$alerts) { $counts{_alert_field($a, $field)}++; }
    my @top2 = (sort { $counts{$b} <=> $counts{$a} } keys %counts)[0,1];
    $top2[0] //= ''; $top2[1] //= '';

    my (%b1, %b2);
    for my $h (0..23) { my $l = sprintf("%02d:00",$h); $b1{$l}=0; $b2{$l}=0; }
    for my $a (@$alerts) {
        my $key = _alert_field($a, $field);
        my $ts  = $a->{start_at} // '';
        my $hr  = ($ts =~ /T(\d{2}):/) ? $1 : 0;
        my $lbl = sprintf("%02d:00", $hr);
        $b1{$lbl}++ if $key eq $top2[0];
        $b2{$lbl}++ if $top2[1] ne '' && $key eq $top2[1];
    }
    my $s1 = '['.join(',', map { sprintf('{"t":"%s","v":%d}', $_, $b1{$_}) } sort keys %b1).']';
    my $s2 = '['.join(',', map { sprintf('{"t":"%s","v":%d}', $_, $b2{$_}) } sort keys %b2).']';
    return '{"series1":'.$s1.',"series2":'.$s2.'}';
}

sub _alert_field {
    my ($a, $field) = @_;
    return $a->{source}{ip}      // '-'  if $field eq 'src_ip';
    return $a->{scenario}        // '-'  if $field eq 'scenario';
    # engine: alerts use 'machine_id' (snake_case)
    return $a->{machine_id}      // $a->{machineId} // '-' if $field eq 'engine';
    # ASN: prefer name, fall back to number
    return $a->{source}{as_name} || $a->{source}{as_number} || '-unresolved AS-';
}

# ── Top N ─────────────────────────────────────────────────────────────────────
sub get_top_n {
    my ($alerts, $field, $n) = @_; $n ||= 3;
    my %counts;
    for my $a (@$alerts) {
        my $k = _alert_field($a, $field);
        $counts{$k}++ if $k && $k ne '-';
    }
    my @sorted = sort { $counts{$b} <=> $counts{$a} } keys %counts;
    return [ map { { label => $_, count => $counts{$_} } } @sorted[0..$n-1] ];
}

# ── Engine info ───────────────────────────────────────────────────────────────
sub get_engine_info {
    my $json = `cscli machines list -o json 2>/dev/null`;
    my $data = load_json($json);
    my @engines;
    if (ref $data eq 'ARRAY') {
        for my $m (@$data) {
            # Handle both camelCase (older) and snake_case (newer) field names
            my $mid  = $m->{machineId}    // $m->{machine_id}    // $m->{MachineId} // '';
            my $ip   = $m->{ipAddress}    // $m->{ip_address}    // $m->{IpAddress} // '';
            my $lu   = $m->{lastHeartbeat}// $m->{last_update}   // $m->{last_heartbeat} // $m->{LastHeartbeat} // '';
            my $ver  = $m->{version}      // $m->{Version}       // '';
            my $name = $m->{name}         // $m->{Name}          // $mid // 'unknown';
            # isOnline reflects CAPI connectivity, not local service health
            # Use service status for local health; keep isOnline for display
            my $online = $m->{isOnline} // $m->{is_online} // $m->{IsOnline} // 0;
            push @engines, {
                name       => $name,
                machine_id => $mid,
                ip_address => $ip,
                last_update=> $lu,
                is_online  => $online,
                version    => $ver,
            };
        }
    }
    return \@engines;
}

# ── Hub ───────────────────────────────────────────────────────────────────────
sub get_hub_counts {
    my $json = `cscli hub list -o json 2>/dev/null`;
    my $data = load_json($json);
    my %counts = (scenarios=>0, parsers=>0, collections=>0, postoverflows=>0);
    return \%counts unless ref $data eq 'HASH';
    for my $k (keys %counts) {
        $counts{$k} = scalar @{$data->{$k}} if ref $data->{$k} eq 'ARRAY';
    }
    return \%counts;
}

# ── Bouncers ──────────────────────────────────────────────────────────────────
sub get_bouncers {
    my $json = `cscli bouncers list -o json 2>/dev/null`;
    my $data = load_json($json);
    return ref $data eq 'ARRAY' ? $data : [];
}

# ── Hub content lists (used by the Hub tab's per-type drilldown views) ───────
# `cscli hub list -o json` wraps content type-keyed: {"scenarios":[...],...}.
# The individual `cscli <type> list -o json` commands are documented the
# same way in some versions but return a bare array in others - unwrap
# whichever shape actually comes back instead of assuming one.
sub _unwrap_hub_items {
    my ($data, $key) = @_;
    return [] unless defined $data;
    return $data if ref $data eq 'ARRAY';
    if (ref $data eq 'HASH') {
        return $data->{$key}  if ref $data->{$key}  eq 'ARRAY';
        return $data->{rows}  if ref $data->{rows}  eq 'ARRAY';
    }
    return [];
}

sub get_scenario_list {
    my $json = run_cscli_json('scenarios', 'list');
    return _unwrap_hub_items(load_json($json), 'scenarios');
}

sub get_parser_list {
    my $json = run_cscli_json('parsers', 'list');
    return _unwrap_hub_items(load_json($json), 'parsers');
}

sub get_postoverflow_list {
    my $json = run_cscli_json('postoverflows', 'list');
    return _unwrap_hub_items(load_json($json), 'postoverflows');
}

sub get_collection_list {
    my $json = run_cscli_json('collections', 'list');
    return _unwrap_hub_items(load_json($json), 'collections');
}

# Raw JSON for a hub list command, exposed so the UI can show a debug
# snippet when parsing comes back empty - useful for diagnosing an
# unexpected shape on a given cscli version without guessing blind.
sub get_hub_list_raw {
    my ($type) = @_;
    return run_cscli_json($type, 'list') // '';
}

# ── Per-bouncer metric breakdown (Bouncers <-> Metrics dive-through) ─────────
# Same tolerant multi-format parsing as parse_bouncer_metrics(), but keeps
# the per-bouncer rows instead of collapsing them into one set of totals.
sub get_bouncer_metrics {
    my $json = `cscli metrics -o json 2>/dev/null`;
    my $data = load_json($json);
    my @rows;

    if (ref $data eq 'HASH' && ref $data->{bouncers} eq 'HASH') {
        for my $name (sort keys %{$data->{bouncers}}) {
            my $b = $data->{bouncers}{$name};
            push @rows, {
                name     => $name,
                bytes    => $b->{dropped_bytes}   || $b->{bytes_written}   || 0,
                packets  => $b->{dropped_packets} || $b->{packets_written} || 0,
                requests => $b->{requests_count}  || $b->{req_processed}   || 0,
            };
        }
    } elsif (ref $data eq 'HASH' && ref $data->{remediation_components} eq 'ARRAY') {
        for my $b (@{$data->{remediation_components}}) {
            push @rows, {
                name     => $b->{name} || $b->{bouncer_name} || 'unknown',
                bytes    => $b->{dropped_bytes}   || 0,
                packets  => $b->{dropped_packets} || 0,
                requests => $b->{requests_count}  || 0,
            };
        }
    } elsif (ref $data eq 'ARRAY') {
        for my $b (@$data) {
            push @rows, {
                name     => $b->{name} || 'unknown',
                bytes    => $b->{dropped_bytes}   || 0,
                packets  => $b->{dropped_packets} || 0,
                requests => $b->{requests_count}  || 0,
            };
        }
    }
    return \@rows;
}

# URL/anchor-safe slug for linking a bouncer row to its metrics anchor.
sub slugify {
    my ($s) = @_; $s //= '';
    $s =~ s/[^A-Za-z0-9_-]+/-/g;
    return lc($s);
}

# ── Format helpers ────────────────────────────────────────────────────────────
sub fmt_bytes {
    my ($b) = @_; $b ||= 0;
    return sprintf("%.2f GB", $b/1e9) if $b >= 1e9;
    return sprintf("%.2f MB", $b/1e6) if $b >= 1e6;
    return sprintf("%.1f KB", $b/1e3) if $b >= 1e3;
    return "$b B";
}

sub fmt_num {
    my ($n) = @_; $n ||= 0;
    return sprintf("%.1fk", $n/1000) if $n >= 1000;
    return "$n";
}

sub html_escape {
    my ($s) = @_; $s //= '';
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;  $s =~ s/"/&quot;/g;
    return $s;
}

1;

# ── Pure SVG sparkline (no JS required) ──────────────────────────────────────
sub svg_sparkline {
    my ($series1, $series2, $w, $h, $c1, $c2) = @_;
    $w ||= 200; $h ||= 70;
    $c1 ||= '#6c63ff'; $c2 ||= '#f5a623';

    my @all_vals = map { $_->{v} } (@$series1, @$series2);
    my $maxV = (sort { $b <=> $a } @all_vals)[0] || 1;

    sub _polyline {
        my ($pts, $maxV, $w, $h, $col, $fill) = @_;
        return '' unless @$pts >= 2;
        my $n = scalar @$pts;
        my @coords;
        for my $i (0..$n-1) {
            my $x = int($i / ($n-1) * $w);
            my $y = int($h - ($pts->[$i]{v} / $maxV) * ($h - 8) - 4);
            push @coords, "$x,$y";
        }
        my $pts_str = join(' ', @coords);
        # close path for fill
        my $fill_pts = $pts_str . " $w,$h 0,$h";
        return qq(<polygon points="$fill_pts" fill="$fill" opacity="0.15"/>)
             . qq(<polyline points="$pts_str" fill="none" stroke="$col" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>);
    }

    # grid lines
    my $grid = '';
    for my $f (0.33, 0.66, 1.0) {
        my $y = int($h - $f * ($h - 8) - 4);
        $grid .= qq(<line x1="0" y1="$y" x2="$w" y2="$y" stroke="rgba(42,52,80,0.6)" stroke-width="1"/>);
    }

    my $lines  = _polyline($series2, $maxV, $w, $h, $c2, $c2);
    $lines    .= _polyline($series1, $maxV, $w, $h, $c1, $c1);

    # max label
    my $label = $maxV >= 1000 ? sprintf("%.1fk", $maxV/1000) : "$maxV";

    return qq(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 $w $h" )
         . qq(style="width:100%;height:${h}px;display:block;overflow:hidden">)
         . qq(<text x="2" y="10" font-size="9" fill="rgba(139,148,158,0.9)" font-family="monospace">$label</text>)
         . $grid . $lines
         . qq(</svg>);
}

# ── CSS stacked bar chart (pure HTML, no JS) ──────────────────────────────────
# $data = [ {label=>'May 25', values=>[10,5,3,...]}, ... ]
# $colors = ['#hex1', '#hex2', ...]
sub css_stacked_bars {
    my ($day_labels, $sc_names, $day_sc, $colors, $h) = @_;
    $h ||= 140;

    # compute max day total for scaling
    my $maxV = 1;
    for my $day (@$day_labels) {
        my $tot = 0;
        $tot += ($day_sc->{$day}{$_} || 0) for @$sc_names;
        $maxV = $tot if $tot > $maxV;
    }

    my $bars_html = '';
    for my $day (@$day_labels) {
        my $tot = 0;
        $tot += ($day_sc->{$day}{$_} || 0) for @$sc_names;
        my $bar_pct = $maxV > 0 ? int($tot / $maxV * 100) : 0;

        my $segments = '';
        my $ci = 0;
        for my $sc (@$sc_names) {
            my $v = $day_sc->{$day}{$sc} || 0;
            next unless $v > 0;
            my $seg_pct = $tot > 0 ? int($v / $tot * 100) : 0;
            my $col = $colors->[$ci % scalar @$colors];
            $segments .= qq(<div style="height:${seg_pct}%;background:$col;min-height:1px" title="$sc: $v"></div>);
            $ci++;
        }

        $bars_html .= qq(<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px">)
                    . qq(<div style="width:100%;flex:1;display:flex;flex-direction:column;justify-content:flex-end">)
                    . qq(<div style="width:80%;margin:0 auto;height:${bar_pct}%;min-height:${\ ($tot>0?2:0) }px;display:flex;flex-direction:column;justify-content:flex-end;overflow:hidden;border-radius:2px 2px 0 0">)
                    . $segments
                    . qq(</div></div>)
                    . qq(<div style="font-size:8px;color:#6e7681;font-family:monospace;white-space:nowrap;text-align:center">$day</div>)
                    . qq(</div>);
    }

    return qq(<div style="height:${h}px;display:flex;gap:2px;align-items:stretch;padding:4px 2px 0">)
         . $bars_html
         . qq(</div>);
}

# ── Timeline as Perl arrays (for SVG, no JS needed) ──────────────────────────
sub get_timeline_data {
    my ($alerts, $field) = @_;
    my %counts;
    for my $a (@$alerts) { $counts{_alert_field($a, $field)}++; }
    my @top2 = (sort { $counts{$b} <=> $counts{$a} } keys %counts)[0,1];
    $top2[0] //= ''; $top2[1] //= '';

    my (%b1, %b2);
    for my $h (0..23) { my $l = sprintf("%02d:00",$h); $b1{$l}=0; $b2{$l}=0; }
    for my $a (@$alerts) {
        my $key = _alert_field($a, $field);
        my $ts  = $a->{start_at} // '';
        my $hr  = ($ts =~ /T(\d{2}):/) ? $1 : 0;
        my $lbl = sprintf("%02d:00", $hr);
        $b1{$lbl}++ if $key eq $top2[0];
        $b2{$lbl}++ if $top2[1] ne '' && $key eq $top2[1];
    }
    my @s1 = map { {t=>$_, v=>$b1{$_}} } sort keys %b1;
    my @s2 = map { {t=>$_, v=>$b2{$_}} } sort keys %b2;
    return (\@s1, \@s2);
}
