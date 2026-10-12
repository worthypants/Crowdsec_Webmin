#!/usr/bin/perl
# CrowdSec Webmin Module - crowdsec-lib.pl

require '../web-lib.pl';
&init_config();
require '../ui-lib.pl';
require './snapshot-lib.pl';

our %text;
&load_language('crowdsec');

# ── JSON loader ───────────────────────────────────────────────────────────────
sub load_json {
    my ($json) = @_;
    return undef unless defined $json && $json =~ /^\s*[\[\{]/;
    eval { require JSON; };
    if ($@) { eval { require JSON::PP; JSON::PP->import('decode_json'); }; }
    my $data = eval { JSON::decode_json($json) };
    return $data;
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
    # Remove journalctl informational lines (-- No entries --, -- Journal begins..., etc.)
    $out =~ s/^--[^\n]*--\s*\n?//gm;
    $out =~ s/^--[^\n]*\n?//gm;
    $out =~ s/^\s+|\s+$//g;
    return $out || '';
}

# ── Alerts ────────────────────────────────────────────────────────────────────
sub get_alerts_detail {
    my ($since) = @_;
    $since = '24h' unless defined $since;
    my $since_flag = ($since eq '' || $since eq 'all') ? '' : "--since \Q$since\E";
    my $json = `cscli alerts list -o json --limit 0 $since_flag 2>/dev/null`;   # default limit is 50!
    my $data = load_json($json);
    return ref $data eq 'ARRAY' ? $data : [];
}

# ── Decisions ─────────────────────────────────────────────────────────────────
sub get_decisions {
    my (%opts) = @_;
    my $json = `cscli decisions list -o json 2>/dev/null`;
    return ([], '') unless $json && $json =~ /\S/;
    return ([], '') if $json =~ /^\s*null\s*$/;

    my $data = load_json($json);
    return ([], $json) unless defined $data;

    # cscli decisions list -o json returns ALERT objects, each with a
    # nested "decisions" array. We flatten them out, merging alert-level
    # fields (source IP, scenario, machine_id) with decision-level fields
    # (type, duration, origin, scope, value, id).
    my @flat;

    my $alert_list;
    if    (ref $data eq 'ARRAY')                                      { $alert_list = $data; }
    elsif (ref $data eq 'HASH' && ref $data->{rows}  eq 'ARRAY')     { $alert_list = $data->{rows}; }
    elsif (ref $data eq 'HASH' && ref $data->{items} eq 'ARRAY')     { $alert_list = $data->{items}; }
    else  { $alert_list = []; }

    for my $alert (@$alert_list) {
        next unless ref $alert eq 'HASH';

        # Alert-level context
        my $scenario   = $alert->{scenario}   // '';
        my $machine_id = $alert->{machine_id} // '';
        my $start_at   = $alert->{start_at}   // '';
        my $src_ip     = $alert->{source}{ip} // $alert->{source}{value} // '';
        my $src_asn    = $alert->{source}{as_name} // $alert->{source}{as_number} // '';
        my $src_cn     = $alert->{source}{cn} // '';

        # Each alert can have multiple decisions
        my $decisions = $alert->{decisions} // [];
        $decisions = [$decisions] if ref $decisions eq 'HASH'; # defensive

        for my $d (@$decisions) {
            next unless ref $d eq 'HASH';
            push @flat, {
                # Decision fields
                id       => $d->{id}       // '',
                type     => $d->{type}     // 'ban',
                origin   => $d->{origin}   // '',
                scope    => $d->{scope}    // 'Ip',
                value    => $d->{value}    // $src_ip,   # IP from decision or alert source
                duration => $d->{duration} // '',
                scenario => $d->{scenario} // $scenario, # decision scenario or alert scenario
                simulated=> $d->{simulated}// 0,
                # Alert context for display
                src_asn  => $src_asn,
                src_cn   => $src_cn,
                machine_id => $machine_id,
                start_at   => $start_at,
            };
        }
    }

    return (\@flat, $json);
}

# ── Metrics ───────────────────────────────────────────────────────────────────
sub parse_bouncer_metrics {
    my %totals = (bytes => 0, packets => 0, active_decisions => 0);

    # ── Primary: cscli metrics show bouncers -o json ──────────────────────────
    # Structure (confirmed from diagnostics):
    # { "bouncers": { "bouncer-name": {
    #     "CAPI":    { "dropped": { "byte": N, "packet": N }, "active_decisions": {"ip": N} },
    #     "crowdsec":{ "dropped": { "byte": N, "packet": N }, "active_decisions": {"ip": N} },
    #     "cscli":   { "dropped": { "byte": N, "packet": N } },
    #     "":        { "processed": { "byte": N, "packet": N } }
    # } } }
    my $json = `cscli metrics show bouncers -o json 2>/dev/null`;
    if ($json && $json =~ /^\s*\{/) {
        my $data = load_json($json);
        if (ref $data eq 'HASH' && ref $data->{bouncers} eq 'HASH') {
            for my $bname (keys %{$data->{bouncers}}) {
                my $b = $data->{bouncers}{$bname};
                next unless ref $b eq 'HASH';
                # Sum dropped bytes/packets across all origin keys (CAPI, crowdsec, cscli, etc.)
                for my $origin (keys %$b) {
                    my $od = $b->{$origin};
                    next unless ref $od eq 'HASH';
                    if (ref $od->{dropped} eq 'HASH') {
                        $totals{bytes}   += $od->{dropped}{byte}   || 0;
                        $totals{packets} += $od->{dropped}{packet} || 0;
                    }
                    if (ref $od->{active_decisions} eq 'HASH') {
                        $totals{active_decisions} += $od->{active_decisions}{ip} || 0;
                    }
                }
            }
            return \%totals;
        }
    }

    # ── Fallback: cscli metrics -o json (older CrowdSec versions) ─────────────
    $json = `cscli metrics -o json 2>/dev/null`;
    if ($json && $json =~ /^\s*[\[\{]/) {
        my $data = load_json($json);
        if (ref $data eq 'HASH' && ref $data->{bouncers} eq 'HASH') {
            for my $b (values %{$data->{bouncers}}) {
                next unless ref $b eq 'HASH';
                $totals{bytes}   += $b->{dropped_bytes}   || 0;
                $totals{packets} += $b->{dropped_packets} || 0;
            }
        }
    }

    return \%totals;
}

# ── Per-origin breakdown for Remediation Metrics page ────────────────────────
sub parse_bouncer_metrics_by_origin {
    my %by_origin;  # { CAPI => {bytes=>N, packets=>N, decisions=>N}, crowdsec => {...} }

    my $json = `cscli metrics show bouncers -o json 2>/dev/null`;
    return \%by_origin unless $json && $json =~ /^\s*\{/;
    my $data = load_json($json);
    return \%by_origin unless ref $data eq 'HASH' && ref $data->{bouncers} eq 'HASH';

    for my $bname (keys %{$data->{bouncers}}) {
        my $b = $data->{bouncers}{$bname};
        next unless ref $b eq 'HASH';
        for my $origin (keys %$b) {
            next if $origin eq '';  # processed totals, not dropped
            my $od = $b->{$origin};
            next unless ref $od eq 'HASH';
            $by_origin{$origin} //= {bytes => 0, packets => 0, decisions => 0};
            if (ref $od->{dropped} eq 'HASH') {
                $by_origin{$origin}{bytes}   += $od->{dropped}{byte}   || 0;
                $by_origin{$origin}{packets} += $od->{dropped}{packet} || 0;
            }
            if (ref $od->{active_decisions} eq 'HASH') {
                $by_origin{$origin}{decisions} += $od->{active_decisions}{ip} || 0;
            }
        }
    }
    return \%by_origin;
}

# ── Active blocked IPs by behaviour and origin ───────────────────────────────
# From the "decisions" section of cscli metrics (an active-decisions gauge):
#   { "ssh:bruteforce": { "CAPI": { "ban": 9530 } }, ... }
# Returns { reason => { origin => count } }
sub get_active_decisions_by_reason {
    my $json = `cscli metrics show decisions -o json 2>/dev/null`;
    my $data = load_json($json);
    return {} unless ref $data eq 'HASH';
    my $d = ref $data->{decisions} eq 'HASH' ? $data->{decisions} : $data;
    my %out;
    for my $reason (keys %$d) {
        next unless ref $d->{$reason} eq 'HASH';
        for my $origin (keys %{$d->{$reason}}) {
            my $acts = $d->{$reason}{$origin};
            my $n = 0;
            if (ref $acts eq 'HASH') { $n += $_ || 0 for values %$acts; } else { $n = $acts || 0; }
            $out{$reason}{$origin} += $n if $n;
        }
    }
    return \%out;
}

# "pop3/imap:bruteforce" -> "POP3/IMAP Bruteforce"; plain scenario names unchanged
sub behaviour_label {
    my ($r) = @_;
    return $r unless defined $r && $r =~ /^([\w\/-]+):([\w-]+)$/ && $r !~ m{^[\w-]+/[\w-]+$};
    my ($svc, $kind) = ($1, $2);
    my %UP = map { $_ => 1 } qw(http https ssh smtp pop3 imap ftp rdp sip vpn dns smb ldap tcp udp);
    $svc = join('/', map { $UP{lc $_} ? uc $_ : ucfirst $_ } split m{/}, $svc);
    $kind =~ s/[-_]/ /g;
    return "$svc " . join(' ', map { ucfirst } split / /, $kind);
}

# Human name for a decision origin
sub origin_label {
    my ($o) = @_;
    return 'Community Blocklist (CAPI)'   if $o eq 'CAPI';
    return 'Your security engine'          if $o eq 'crowdsec';
    return 'Manual bans (cscli)'           if $o eq 'cscli';
    return 'Console decisions'             if $o eq 'console';
    return "Blocklist: $1"                 if $o =~ /^lists:(.+)$/;
    return $o;
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
    if ($field eq 'src_ip') {
        # Only return a plain IP address — ranges don't belong in the IP chart
        my $ip = $a->{source}{ip} // '';
        return $ip if $ip =~ /^\d+\.\d+\.\d+\.\d+$/;
        # For range-type alerts, show the range value so it appears somewhere
        my $val = $a->{source}{value} // '';
        return $val if $val =~ /^\d+\.\d+\.\d+\.\d+\/\d+$/;
        return '-';
    }
    return $a->{scenario}                           // '-'  if $field eq 'scenario';
    return $a->{machine_id} // $a->{machineId}      // '-'  if $field eq 'engine';
    # ASN
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
    my $total = 0;
    $total += $_ for values %counts;
    my @sorted = sort { $counts{$b} <=> $counts{$a} } keys %counts;
    my $list = [ map { { label => $_, count => $counts{$_} } } @sorted[0..$n-1] ];
    return wantarray ? ($list, $total, scalar keys %counts) : $list;
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

# Count hub items (across all sections) whose installed version is behind the
# hub's latest version — used by the health-status check on the Engines tab.
sub get_hub_updates_count {
    my $json = `cscli hub list -o json 2>/dev/null`;
    my $data = load_json($json);
    return 0 unless ref $data eq 'HASH';
    my $n = 0;
    for my $k (qw(scenarios parsers collections postoverflows)) {
        next unless ref $data->{$k} eq 'ARRAY';
        for my $item (@{$data->{$k}}) {
            my $ver = $item->{version} // '';
            my $lv  = $item->{local_version} // '';
            $n++ if $lv && $ver && $lv ne $ver;
        }
    }
    return $n;
}

# ── Bouncers ──────────────────────────────────────────────────────────────────
sub get_bouncers {
    my $json = `cscli bouncers list -o json 2>/dev/null`;
    my $data = load_json($json);
    return ref $data eq 'ARRAY' ? $data : [];
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

# ── Smooth SVG area chart (no JS required) ───────────────────────────────────
# Monotone cubic interpolation: curves pass through every data point and never
# overshoot (so a smoothed line can't dip below zero between two buckets).
sub _smooth_path {
    my ($xs, $ys) = @_;
    my $n = scalar @$xs;
    return '' if $n < 2;
    my (@d, @m);
    for my $i (0..$n-2) {
        my $dx = ($xs->[$i+1] - $xs->[$i]) || 1;
        $d[$i] = ($ys->[$i+1] - $ys->[$i]) / $dx;
    }
    $m[0] = $d[0]; $m[$n-1] = $d[$n-2];
    for my $i (1..$n-2) {
        $m[$i] = ($d[$i-1] * $d[$i] <= 0) ? 0 : 2 / (1/$d[$i-1] + 1/$d[$i]);
    }
    my $p = sprintf("M%.1f,%.1f", $xs->[0], $ys->[0]);
    for my $i (0..$n-2) {
        my $dx = ($xs->[$i+1] - $xs->[$i]) / 3;
        $p .= sprintf(" C%.1f,%.1f %.1f,%.1f %.1f,%.1f",
            $xs->[$i] + $dx,   $ys->[$i]   + $m[$i]   * $dx,
            $xs->[$i+1] - $dx, $ys->[$i+1] - $m[$i+1] * $dx,
            $xs->[$i+1],       $ys->[$i+1]);
    }
    return $p;
}

our $_SPARK_SEQ = 0;
sub svg_sparkline {
    my ($series1, $series2, $w, $h, $meta, $c1, $c2) = @_;
    $w ||= 300; $h ||= 64;
    $c1 ||= '#7c74ff'; $c2 ||= '#d9763f';
    $meta ||= {};
    my $id = 'spk' . (++$_SPARK_SEQ);

    my @all_vals = map { $_->{v} } (@$series1, @$series2);
    my $maxV = (sort { $b <=> $a } @all_vals)[0] || 0;
    my $scale = $maxV || 1;
    my $n   = scalar @$series1;
    my $top = 6; my $base = $h - 1;

    my $area = sub {
        my ($pts, $col, $gid) = @_;
        return '' unless @$pts >= 2 && grep { $_->{v} > 0 } @$pts;
        my (@xs, @ys);
        for my $i (0..$#$pts) {
            push @xs, $i / $#$pts * $w;
            push @ys, $base - ($pts->[$i]{v} / $scale) * ($base - $top);
        }
        my $line = _smooth_path(\@xs, \@ys);
        return qq(<path d="$line L$w,$h L0,$h Z" fill="url(#$gid)"/>)
             . qq(<path d="$line" fill="none" stroke="$col" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>);
    };

    my $defs = '';
    for my $g ([ "${id}a", $c1 ], [ "${id}b", $c2 ]) {
        $defs .= qq(<linearGradient id="$g->[0]" x1="0" y1="0" x2="0" y2="1">)
               . qq(<stop offset="0" stop-color="$g->[1]" stop-opacity="0.32"/>)
               . qq(<stop offset="1" stop-color="$g->[1]" stop-opacity="0"/></linearGradient>);
    }

    # recessive grid: baseline + two faint guides
    my $grid = '';
    for my $f (0.5, 1.0) {
        my $y = sprintf("%.1f", $base - $f * ($base - $top));
        $grid .= qq(<line x1="0" y1="$y" x2="$w" y2="$y" stroke="rgba(139,148,158,0.13)" stroke-width="1" stroke-dasharray="3 4" vector-effect="non-scaling-stroke"/>);
    }
    $grid .= qq(<line x1="0" y1="$base" x2="$w" y2="$base" stroke="rgba(139,148,158,0.3)" stroke-width="1" vector-effect="non-scaling-stroke"/>);

    my $marks = $area->($series2, $c2, "${id}b") . $area->($series1, $c1, "${id}a");

    # hover: one invisible column per bucket with a native tooltip (no JS)
    my $hits = '';
    if ($n >= 2) {
        my $bw = $w / $n;
        my ($n1, $n2) = (html_escape($meta->{name1} // ''), html_escape($meta->{name2} // ''));
        for my $i (0..$n-1) {
            my $tip = html_escape($series1->[$i]{t} // '');
            $tip .= "\n$n1: $series1->[$i]{v}" if $n1 ne '';
            $tip .= "\n$n2: $series2->[$i]{v}" if $n2 ne '' && $series2->[$i];
            my $x = sprintf("%.1f", $i * $bw);
            my $bwf = sprintf("%.1f", $bw);
            $hits .= qq(<rect class="spk-hit" x="$x" y="0" width="$bwf" height="$h"><title>$tip</title></rect>);
        }
    }

    my $label = $maxV >= 1000 ? sprintf("%.1fk", $maxV/1000) : "$maxV";
    my $from  = html_escape($meta->{from} // '');
    my $to    = html_escape($meta->{to}   // '');
    my $empty = $maxV ? '' : qq(<div class="spk-empty">no alerts in this period</div>);

    return qq(<div class="spk">$empty)
         . qq(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 $w $h" preserveAspectRatio="none" )
         . qq(style="width:100%;height:${h}px;display:block"><defs>$defs</defs>)
         . $grid . $marks . $hits
         . qq(</svg><div class="spk-axis"><span>$from</span><span>peak $label / bucket</span><span>$to</span></div></div>);
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
            my $col = $colors->[$ci % scalar @$colors];   # colour follows the scenario, not its position
            $ci++;
            next unless $v > 0;
            $segments .= qq(<div class="sbar-seg" style="flex:$v 1 0;background:$col;min-height:2px" title="$day\n$sc: $v"></div>);
            
        }

        $bars_html .= qq(<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px">)
                    . qq(<div style="width:100%;flex:1;display:flex;flex-direction:column;justify-content:flex-end">)
                    . qq(<div style="width:80%;margin:0 auto;height:${bar_pct}%;min-height:${\ ($tot>0?2:0) }px;display:flex;flex-direction:column;justify-content:flex-end;gap:2px;overflow:hidden;border-radius:4px 4px 0 0;max-width:34px">)
                    . $segments
                    . qq(</div></div>)
                    . qq(<div style="font-size:8px;color:#6e7681;font-family:monospace;white-space:nowrap;text-align:center">$day</div>)
                    . qq(</div>);
    }

    return qq(<div style="height:${h}px;display:flex;gap:4px;align-items:stretch;padding:4px 2px 0;border-bottom:0">)
         . $bars_html
         . qq(</div>);
}

# ── Timeline as Perl arrays (for SVG, no JS needed) ──────────────────────────
# Buckets run chronologically across the selected time range (oldest → now).
sub get_timeline_data {
    my ($alerts, $field, $since) = @_;
    $since ||= '24h';
    require Time::Local;
    require POSIX;

    my %counts;
    for my $a (@$alerts) { $counts{_alert_field($a, $field)}++; }
    my @top2 = (sort { $counts{$b} <=> $counts{$a} || $a cmp $b } keys %counts)[0,1];
    $top2[0] //= ''; $top2[1] //= '';

    # alert timestamps are UTC ISO-8601
    my @rows;
    for my $a (@$alerts) {
        next unless ($a->{start_at} // '') =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/;
        my $t = eval { Time::Local::timegm($6, $5, $4, $3, $2-1, $1) } or next;
        push @rows, [$t, _alert_field($a, $field)];
    }

    my %WIN = ('1h'=>[3600,12], '24h'=>[86400,24], '3d'=>[3*86400,36],
               '7d'=>[7*86400,28], '15d'=>[15*86400,30], '30d'=>[30*86400,30]);
    my $now = time();
    my ($span, $nb);
    if ($WIN{$since}) { ($span, $nb) = @{$WIN{$since}}; }
    else {   # all time: from the oldest alert
        my $oldest = $now - 86400;
        for (@rows) { $oldest = $_->[0] if $_->[0] < $oldest; }
        $span = $now - $oldest + 1; $nb = 30;
    }
    my $start = $now - $span;
    my $bsize = $span / $nb;
    my $fmt   = $span <= 86400 ? '%H:%M' : ($span <= 3*86400 ? '%d %b %H:%M' : '%d %b');

    my (@s1, @s2);
    for my $i (0..$nb-1) {
        my $lbl = POSIX::strftime($fmt, localtime($start + $i * $bsize)) . ' – '
                . POSIX::strftime($fmt, localtime($start + ($i+1) * $bsize));
        push @s1, {t=>$lbl, v=>0}; push @s2, {t=>$lbl, v=>0};
    }
    for my $r (@rows) {
        my $i = int(($r->[0] - $start) / $bsize);
        next if $i < 0; $i = $nb-1 if $i >= $nb;
        $s1[$i]{v}++ if $r->[1] eq $top2[0];
        $s2[$i]{v}++ if $top2[1] ne '' && $r->[1] eq $top2[1];
    }
    my %meta = (name1=>$top2[0], name2=>$top2[1],
                from=>POSIX::strftime($fmt, localtime($start)), to=>'now');
    return (\@s1, \@s2, \%meta);
}

# ── CIDR / IP range filtering ─────────────────────────────────────────────────

# Convert a CIDR string like "198.51.100.0/24" or a plain IP "1.2.3.4"
# into (network_int, mask_int) pair for fast matching.
sub _cidr_to_range {
    my ($cidr) = @_;
    $cidr =~ s/\s+//g;
    my ($ip_str, $prefix) = split '/', $cidr;
    $prefix //= 32;
    my @octs = split /\./, $ip_str;
    return () unless @octs == 4;
    my $ip_int = 0;
    for my $o (@octs) { $ip_int = ($ip_int << 8) | ($o & 0xFF); }
    my $mask = $prefix == 0 ? 0 : (0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF;
    my $net  = $ip_int & $mask;
    return ($net, $mask);
}

# Return 1 if $ip_str falls within any of the @cidrs
sub ip_in_cidrs {
    my ($ip_str, @cidrs) = @_;
    return 0 unless defined $ip_str && $ip_str =~ /^\d+\.\d+\.\d+\.\d+$/;
    my @octs = split /\./, $ip_str;
    return 0 unless @octs == 4;
    my $ip_int = 0;
    for my $o (@octs) { $ip_int = ($ip_int << 8) | ($o & 0xFF); }
    for my $cidr (@cidrs) {
        my ($net, $mask) = _cidr_to_range($cidr);
        next unless defined $mask;
        return 1 if ($ip_int & $mask) == $net;
    }
    return 0;
}

# Filter an alerts array, removing alerts whose source IP is in @exclude_cidrs.
sub filter_alerts {
    my ($alerts, @exclude_cidrs) = @_;
    return $alerts unless @exclude_cidrs;

    # Safety: validate that every CIDR is sane before filtering anything
    my @valid_cidrs = grep { /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/ } @exclude_cidrs;
    return $alerts unless @valid_cidrs;

    my @out;
    for my $a (@$alerts) {
        my $ip  = $a->{source}{ip}    // '';
        my $val = $a->{source}{value} // $ip;
        # Only exclude if IP explicitly matches a test range
        next if $ip  && ip_in_cidrs($ip,  @valid_cidrs);
        if ($val =~ m{^(\d+\.\d+\.\d+\.\d+)(?:/\d+)?$}) {
            next if ip_in_cidrs($1, @valid_cidrs);
        }
        push @out, $a;
    }
    return \@out;
}

# Default test ranges (RFC 5737 documentation ranges)
our @TEST_IP_RANGES = ('198.51.100.0/24', '192.0.2.0/24');

# ── Config via Webmin's native %config (populated by init_config in web-lib.pl) ─
# Saved with save_module_config() in config.cgi → /etc/webmin/crowdsec/config

# ── Config via Webmin's module config API ─────────────────────────────────────
# get_module_config() reads /etc/webmin/crowdsec/config reliably in all contexts

sub get_test_ip_ranges {
    my $ranges = $config{test_ip_ranges};
    if (!defined $ranges || $ranges eq '') {
        my %mc = &get_module_config();
        $ranges = $mc{test_ip_ranges};
    }
    $ranges //= '198.51.100.0/24 192.0.2.0/24';
    # Type 9 (multiline textarea) stores newlines as spaces
    # Handle all separator formats
    $ranges =~ s/\\n/ /g;
    $ranges =~ s/,/ /g;
    $ranges =~ s/\n/ /g;
    return grep { /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/ }
           grep { /\S/ }
           split /\s+/, $ranges;
}

sub get_exclude_by_default {
    my $val = $config{exclude_by_default};
    if (!defined $val) {
        my %mc = &get_module_config();
        $val = $mc{exclude_by_default};
    }
    # Handle Yes/No strings (from config.info type 1) as well as 1/0
    return 0 unless defined $val;
    return 0 if $val eq '0' || lc($val) eq 'no';
    return 1 if $val eq '1' || lc($val) eq 'yes';
    return $val ? 1 : 0;
}
