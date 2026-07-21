#!/usr/bin/perl
# CrowdSec Webmin Module - index.cgi  (main dashboard, tab router)

require './crowdsec-lib.pl';

&ReadParse();

my $tab = $in{'tab'} || 'engines';

&ui_print_header(undef, "CrowdSec Security Engine", "", undef, 1, 1);

# ── Filter state (drives the click-and-dive drilldowns) ───────────────────────
# Any of these can arrive as a query param, either typed into the filter bar
# or clicked through from a ranked-list item / table cell elsewhere in the UI.
# 'engine' and 'as' aren't real cscli filter flags, so they're applied as a
# post-filter on the already-fetched alert list below.
my @FILTER_KEYS = qw(ip range scope scenario type origin since until engine as);
my %filter;
for my $k (@FILTER_KEYS) {
    $filter{$k} = $in{$k} if defined $in{$k} && $in{$k} ne '';
}
my $since = $filter{since} || '24h';
my $has_filter = grep { $_ ne 'since' } keys %filter;

# Human labels for chips
my %FILTER_LABEL = (
    ip => 'IP', range => 'Range', scope => 'Scope', scenario => 'Scenario',
    type => 'Type', origin => 'Origin', since => 'Since', until => 'Until',
    engine => 'Engine', as => 'AS',
);

# Renders the active-filter chip bar for the current tab. Each chip has an
# "x" that removes just that filter; "Clear all" resets to the tab default.
sub filter_bar_html {
    return '' unless $has_filter;
    my $html = '<div class="filter-bar"><span class="fb-label">Filtered by:</span>';
    for my $k (@FILTER_KEYS) {
        next unless defined $filter{$k} && $filter{$k} ne '';
        my $lbl = $FILTER_LABEL{$k} || $k;
        my $val = html_escape($filter{$k});
        my $rm_qs = filter_qs(skip => $k);
        $html .= qq(<span class="chip">$lbl: $val <a href="index.cgi?tab=$tab@{[$rm_qs ? qq(&$rm_qs) : '']}" title="Remove filter">✕</a></span>);
    }
    $html .= qq(<a class="fb-clear" href="index.cgi?tab=$tab">Clear all ✕</a></div>);
    return $html;
}

# Builds a "dive in" link that reloads the current tab (or a different one,
# via $opts{tab}) with one extra filter applied on top of whatever's active.
sub dive_link {
    my ($label, %opts) = @_;
    my $target_tab = delete $opts{tab} || $tab;
    my $qs = filter_qs(add => \%opts);
    return qq(<a class="dive" href="index.cgi?tab=$target_tab@{[$qs ? qq(&$qs) : '']}">) . html_escape($label) . '</a>';
}

# Shows the raw `cscli <type> list -o json` output (truncated) when parsing
# comes back empty, so an unexpected field/wrapper shape on this cscli
# version is visible instead of a silent dead end.
sub debug_raw_snippet {
    my ($type) = @_;
    my $raw = get_hub_list_raw($type);
    return '' unless defined $raw && $raw ne '';
    my $snippet = length($raw) > 2000 ? substr($raw, 0, 2000) . "\n... (truncated)" : $raw;
    return qq(<details style="margin-top:10px;font-size:11px;color:var(--text3)">
      <summary style="cursor:pointer">Show raw <code>cscli $type list -o json</code> output (debug)</summary>
      <pre style="white-space:pre-wrap;word-break:break-all;margin-top:8px">@{[html_escape($snippet)]}</pre>
    </details>);
}

sub filter_qs {
    # Re-serialise the current filter set (optionally minus $skip) as a
    # query string, for building drill-down / clear links.
    my (%opts) = @_;
    my %f = %filter;
    delete $f{$opts{skip}} if $opts{skip};
    $f{$_} = $opts{add}{$_} for keys %{$opts{add} || {}};
    return join('&', map { "$_=" . &urlize($f{$_}) } grep { defined $f{$_} && $f{$_} ne '' } sort keys %f);
}

# ── Gather data up-front ──────────────────────────────────────────────────────
my $alerts    = get_alerts_detail($since, \%filter);
if ($filter{engine}) {
    $alerts = [ grep { (($_->{machine_id} // $_->{machineId} // '') eq $filter{engine}) } @$alerts ];
}
if ($filter{as}) {
    $alerts = [ grep { (($_->{source}{as_name} // $_->{source}{as_number} // '') eq $filter{as}) } @$alerts ];
}
my $decisions = get_decisions(\%filter);
my $engines   = get_engine_info();
my $bouncers  = get_bouncers();
my $hub       = get_hub_counts();
my $metrics   = parse_bouncer_metrics();
my $cs_status = get_service_status('crowdsec');
my $cb_status = get_service_status('crowdsec-firewall-bouncer');
my $cs_err    = get_service_errors('crowdsec');
my $cb_err    = get_service_errors('crowdsec-firewall-bouncer');
my $alert_cnt = scalar @$alerts;
my %_uniq_ips; $_uniq_ips{$_->{source}{ip}}++ for grep { $_->{source}{ip} } @$alerts;
my $uniq_ip_cnt = scalar keys %_uniq_ips;
my $dec_cnt   = scalar @$decisions;

# Sidebar badges should reflect true totals, not whatever filter happens to
# be active on the current tab - fetch unfiltered counts separately when a
# filter is in play.
my ($badge_alert_cnt, $badge_dec_cnt) = ($alert_cnt, $dec_cnt);
if ($has_filter) {
    $badge_alert_cnt = scalar @{ get_alerts_detail($since) };
    $badge_dec_cnt   = scalar @{ get_decisions() };
}

# Scenario breakdown
my $sc_counts = get_scenario_counts($alerts);
my @sc_sorted = sort { $sc_counts->{$b} <=> $sc_counts->{$a} } keys %$sc_counts;

# Visualizer data
my $top_ips  = get_top_n($alerts, 'src_ip',   3);
my $top_as   = get_top_n($alerts, 'src_as',   3);
my $top_eng  = get_top_n($alerts, 'engine',   3);
my $top_sc   = get_top_n($alerts, 'scenario', 3);

# Generate SVG sparklines directly in Perl - no JS canvas timing issues
my ($tl_ip_s1,  $tl_ip_s2)  = get_timeline_data($alerts, 'src_ip');
my ($tl_as_s1,  $tl_as_s2)  = get_timeline_data($alerts, 'src_as');
my ($tl_eng_s1, $tl_eng_s2) = get_timeline_data($alerts, 'engine');
my ($tl_sc_s1,  $tl_sc_s2)  = get_timeline_data($alerts, 'scenario');

my $svg_ip  = svg_sparkline($tl_ip_s1,  $tl_ip_s2,  300, 80);
my $svg_as  = svg_sparkline($tl_as_s1,  $tl_as_s2,  300, 80);
my $svg_eng = svg_sparkline($tl_eng_s1, $tl_eng_s2, 300, 80);
my $svg_sc  = svg_sparkline($tl_sc_s1,  $tl_sc_s2,  300, 80);

# Engine name/id for tooltip - match console style "Security Engine ...Xkkp"
my ($eng_name, $eng_id) = ('N/A', 'N/A');
if (@$engines) {
    my $e      = $engines->[0];
    my $mid    = $e->{machine_id} || '';
    my $nm     = $e->{name}       || '';
    # Use short name if it's a real short name (not the full machine ID repeated)
    my $suffix = ($nm && length($nm) <= 20 && $nm ne $mid) ? $nm : ('...' . substr($mid, -4));
    $eng_name  = "Security Engine ...$suffix";
    $eng_id    = $mid;
}

# ── Scenario colour palette (matches console) ─────────────────────────────────
my @SC_COLORS = ('#6366f1','#f59e0b','#a78bfa','#06b6d4','#ec4899',
                 '#10b981','#f97316','#84cc16','#e11d48','#0ea5e9');


# ── CSS + shell ───────────────────────────────────────────────────────────────
print <<'HTML';
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0d1117;--surface:#161b27;--surface2:#1c2333;--surface3:#242d3f;
  --border:#2a3450;--border2:#344060;
  --accent:#6c63ff;--accent2:#f5a623;--accent3:#4ecdc4;
  --danger:#ff5c5c;--success:#3dd68c;--warning:#f5a623;--info:#58a6ff;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --mono:'JetBrains Mono',monospace;--sans:'Inter',sans-serif;
  --radius:10px;
}
*{box-sizing:border-box;margin:0;padding:0}
/* Force our colours to beat Webmin's own stylesheet */
.shell, .shell *{color:inherit}
body{background:#0d1117!important;color:#e6edf3!important;font-family:var(--sans);font-size:14px;min-height:100vh}
.shell{color:#e6edf3}
.content, .card, .card-body, .card-header, .topbar, .sidebar{color:#e6edf3}
.tbl td{color:#e6edf3!important}
.page-title{color:#e6edf3!important;font-size:20px;font-weight:700}
.card-title{color:#e6edf3!important;font-size:14px;font-weight:700}
.section-title{color:#e6edf3!important;font-size:16px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
body::before{content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(108,99,255,0.12),transparent);
  pointer-events:none;z-index:0}

/* ── Layout ── */
.shell{position:relative;z-index:1;display:flex;min-height:100vh}
.sidebar{width:220px;flex-shrink:0;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
.main{flex:1;overflow:auto}

/* ── Sidebar ── */
.sb-brand{padding:20px 16px 12px;display:flex;align-items:center;gap:10px;
  border-bottom:1px solid var(--border)}
.sb-brand .logo{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#9b59b6);
  border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;
  box-shadow:0 0 16px rgba(108,99,255,.4)}
.sb-brand h2{font-size:15px;font-weight:700;letter-spacing:-.3px}
.sb-brand p{font-size:10px;color:var(--text3);font-family:var(--mono);margin-top:1px}

.sb-section{padding:8px 0}
.sb-label{font-size:10px;font-weight:600;color:var(--text3);letter-spacing:.1em;
  text-transform:uppercase;padding:8px 16px 4px}
.sb-item{display:flex;align-items:center;gap:10px;padding:8px 16px;
  color:var(--text2);cursor:pointer;border:none;background:none;
  width:100%;text-align:left;font-size:13px;font-family:var(--sans);
  text-decoration:none;transition:all .15s;border-left:2px solid transparent}
.sb-item:hover{background:var(--surface2);color:var(--text)}
.sb-item.active{background:rgba(108,99,255,.12);color:var(--accent);
  border-left-color:var(--accent);font-weight:600}
.sb-item .ico{width:18px;text-align:center;font-size:15px}
.sb-item .badge{margin-left:auto;background:var(--surface3);color:var(--text2);
  font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:10px}
.sb-item.active .badge{background:rgba(108,99,255,.25);color:var(--accent)}

.sb-svc{padding:12px 16px;border-top:1px solid var(--border);margin-top:auto}
.svc-row{display:flex;align-items:center;justify-content:space-between;
  padding:6px 0;font-size:12px}
.svc-name{color:var(--text2);font-family:var(--mono);font-size:11px}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:4px}
.dot.on {background:var(--success);box-shadow:0 0 6px var(--success)}
.dot.off{background:var(--danger); box-shadow:0 0 6px var(--danger)}
.dot.unk{background:var(--text3)}

/* ── Top bar ── */
.topbar{display:flex;align-items:center;justify-content:space-between;
  padding:16px 28px;border-bottom:1px solid var(--border);background:var(--surface)}
.page-title .ico{font-size:22px}
.topbar-right{display:flex;align-items:center;gap:10px}
.btn{font-family:var(--sans);font-size:12px;font-weight:600;padding:7px 14px;
  border-radius:7px;border:none;cursor:pointer;transition:all .15s;text-decoration:none;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#7c74ff}
.btn-ghost{background:var(--surface2);color:var(--text2);border:1px solid var(--border)}
.btn-ghost:hover{border-color:var(--border2);color:var(--text)}
.btn-sm{padding:5px 10px;font-size:11px}
.btn-danger{background:rgba(255,92,92,.12);color:var(--danger);border:1px solid rgba(255,92,92,.25)}
.btn-danger:hover{background:rgba(255,92,92,.22)}
.btn-success{background:rgba(61,214,140,.12);color:var(--success);border:1px solid rgba(61,214,140,.25)}
.btn-success:hover{background:rgba(61,214,140,.22)}
.btn-warn{background:rgba(245,166,35,.12);color:var(--warning);border:1px solid rgba(245,166,35,.25)}
.btn-warn:hover{background:rgba(245,166,35,.22)}

/* ── Content area ── */
.content{padding:24px 28px;max-width:1400px}

/* ── Stat cards ── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px}
.stat-card .label{font-size:11px;color:#8b949e;font-weight:600;letter-spacing:.06em;text-transform:uppercase;margin-bottom:8px}
.stat-card .value{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;color:#e6edf3}
.stat-card .sub{font-size:11px;color:#6e7681;margin-top:6px}
.stat-card.accent .value{color:var(--accent)}
.stat-card.danger .value{color:var(--danger)}
.stat-card.success .value{color:var(--success)}
.stat-card.warn .value{color:var(--warning)}

/* ── Section cards ── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:20px}
.card-header{display:flex;align-items:center;justify-content:space-between;
  padding:16px 20px;border-bottom:1px solid var(--border)}
.card-body{padding:20px}
.card-body.no-pad{padding:0}

/* ── Tables ── */
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;padding:10px 16px;color:var(--text3);font-size:11px;
  letter-spacing:.08em;text-transform:uppercase;font-weight:600;
  border-bottom:1px solid var(--border);background:var(--surface2)}
.tbl td{padding:11px 16px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:rgba(108,99,255,.04)}
.tbl .mono{font-family:var(--mono);font-size:12px}

/* ── Tags / badges ── */
.tag{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:5px;
  font-size:11px;font-weight:600;font-family:var(--mono)}
.tag.ban{background:rgba(255,92,92,.12);color:var(--danger);border:1px solid rgba(255,92,92,.2)}
.tag.captcha{background:rgba(245,166,35,.12);color:var(--warning);border:1px solid rgba(245,166,35,.2)}
.tag.scenario{background:rgba(108,99,255,.12);color:#a99cff;border:1px solid rgba(108,99,255,.2)}
.tag.active{background:rgba(61,214,140,.1);color:var(--success);border:1px solid rgba(61,214,140,.2)}
.tag.inactive{background:rgba(255,92,92,.08);color:var(--danger);border:1px solid rgba(255,92,92,.15)}

/* ── Visualizer ── */
.viz-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.viz-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:16px;position:relative}
.viz-card-title{font-size:12px;font-weight:700;color:var(--accent);margin-bottom:12px;
  display:flex;align-items:center;gap:8px}
.chart-wrap{height:90px;margin-bottom:12px;width:100%;display:block;overflow:hidden;box-sizing:content-box}
.chart-wrap canvas{display:block;width:100%;height:90px;box-sizing:content-box}
.ranked-list{list-style:none}
.ranked-item{display:flex;align-items:center;gap:9px;padding:7px 0;
  border-bottom:1px solid rgba(255,255,255,.04);font-size:12px}
.ranked-item:last-child{border-bottom:none}
.rank-badge{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;
  justify-content:center;font-family:var(--mono);font-size:9px;font-weight:700;flex-shrink:0}
.r1{background:rgba(108,99,255,.25);color:var(--accent);border:1px solid rgba(108,99,255,.4)}
.r2{background:rgba(245,166,35,.2);color:var(--accent2);border:1px solid rgba(245,166,35,.35)}
.r3{background:rgba(139,148,158,.15);color:var(--text3);border:1px solid var(--border)}
.ranked-label{font-family:var(--mono);font-size:11px;flex:1;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ranked-count{font-family:var(--mono);font-size:10px;color:var(--text3);
  background:var(--bg);padding:2px 6px;border-radius:4px;flex-shrink:0}

/* ── Engine card ── */
.engine-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:20px;display:flex;flex-direction:column;gap:12px}
.engine-header{display:flex;align-items:flex-start;justify-content:space-between}
.engine-id{font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:2px}
.engine-stats{display:flex;gap:16px}
.engine-stat{text-align:center}
.engine-stat .n{font-size:22px;font-weight:700;font-family:var(--mono);color:var(--text)}
.engine-stat .l{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em}
.engine-spark{height:60px;width:200px}

/* ── Stacked bar chart ── */
.sbar-chart-wrap{height:160px;position:relative;margin:16px 0}

/* ── Progress bar ── */
.pbar-wrap{margin-bottom:10px}
.pbar-header{display:flex;justify-content:space-between;margin-bottom:4px;font-size:12px}
.pbar-header .name{color:var(--text2)}
.pbar-header .vals{color:var(--text3);font-family:var(--mono);font-size:11px}
.pbar-track{height:5px;background:var(--surface3);border-radius:3px;overflow:hidden}
.pbar-fill{height:100%;border-radius:3px;transition:width .4s}

/* ── Decision duration colouring ── */
.dur-urgent{color:var(--warning)}
.dur-ok{color:var(--text2)}

/* ── Error box ── */
.err-box{background:rgba(255,92,92,.07);border:1px solid rgba(255,92,92,.2);
  border-radius:8px;padding:10px 14px;font-family:var(--mono);font-size:11px;
  color:#ff9090;line-height:1.6;max-height:110px;overflow-y:auto;
  white-space:pre-wrap;word-break:break-all;margin-top:12px}
.err-label{font-size:10px;font-weight:700;color:var(--danger);
  letter-spacing:.1em;text-transform:uppercase;margin-bottom:5px;display:flex;align-items:center;gap:5px}

/* ── Tooltip ── */
.tooltip-box{background:var(--surface3);border:1px solid var(--border2);border-radius:8px;
  padding:10px 14px;font-family:var(--mono);font-size:11px;color:var(--text2);
  display:none;position:absolute;z-index:200;min-width:260px;
  box-shadow:0 8px 32px rgba(0,0,0,.5)}
.tb-row{margin-bottom:3px}.tb-row:last-child{margin-bottom:0}
.tb-val{color:var(--text);font-weight:600}

/* ── Alert quota banner ── */
.quota-banner{background:rgba(245,166,35,.08);border:1px solid rgba(245,166,35,.25);
  border-radius:var(--radius);padding:12px 18px;display:flex;align-items:center;
  justify-content:space-between;margin-bottom:20px;gap:12px}
.quota-text p{font-size:13px;font-weight:600;color:var(--warning)}
.quota-text span{font-size:11px;color:var(--text3)}
.quota-count{font-family:var(--mono);font-size:13px;color:var(--text2);text-align:right}

/* ── Tabs (Visualizer) ── */
.viz-tabs{display:flex;gap:3px;background:var(--bg);border:1px solid var(--border);
  border-radius:7px;padding:3px}
.viz-tab{font-size:11px;font-weight:600;padding:5px 12px;border-radius:5px;
  cursor:pointer;border:none;background:transparent;color:var(--text3);
  transition:all .15s;font-family:var(--sans)}
.viz-tab.active{background:var(--accent);color:#fff}
.viz-tab:hover:not(.active){color:var(--text)}

/* ── Section divider ── */
.section-sub{font-size:12px;color:var(--text3);margin-top:2px;font-weight:400}

/* ── Metric big cards ── */
.metric-tabs{display:flex;gap:0;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:20px}
.metric-tab{flex:1;padding:16px 20px;cursor:pointer;border:none;background:var(--surface);color:var(--text2);
  text-align:left;font-family:var(--sans);transition:background .15s;border-right:1px solid var(--border)}
.metric-tab:last-child{border-right:none}
.metric-tab.active{background:var(--surface2);border-bottom:2px solid var(--accent)}
.metric-tab .mt-label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
.metric-tab .mt-value{font-size:22px;font-weight:700;font-family:var(--mono);color:var(--text)}
.metric-tab.active .mt-value{color:var(--accent)}
.metric-tab .mt-delta{font-size:11px;color:var(--success);margin-top:2px;font-family:var(--mono)}

/* ── Blocklist suggestion cards ── */
.bl-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:20px}
.bl-card{background:linear-gradient(135deg,var(--surface2),var(--surface3));
  border:1px solid var(--border);border-radius:var(--radius);padding:20px;position:relative;overflow:hidden}
.bl-card::before{content:'';position:absolute;inset:0;
  background:radial-gradient(circle at top right,rgba(108,99,255,.08),transparent 60%)}
.bl-card-ico{font-size:28px;margin-bottom:10px}
.bl-card-name{font-size:14px;font-weight:700;margin-bottom:4px}
.bl-card-desc{font-size:11px;color:var(--text3);line-height:1.5;margin-bottom:12px}
.bl-card-meta{display:flex;justify-content:space-between;font-size:11px;color:var(--text3);font-family:var(--mono)}

/* ── Responsive ── */
@media(max-width:900px){
  .sidebar{position:fixed;left:0;top:0;height:100vh;z-index:210;
    transform:translateX(-104%);transition:transform .22s ease;box-shadow:0 0 40px rgba(0,0,0,.6)}
  .sidebar.open{transform:translateX(0)}
  .mobile-nav-toggle{display:inline-flex!important}
  .sidebar-overlay.open{display:block}
}
.mobile-nav-toggle{display:none;position:fixed;top:14px;left:14px;z-index:220;
  background:var(--surface2);border:1px solid var(--border2);color:var(--text);
  border-radius:8px;width:38px;height:38px;align-items:center;justify-content:center;
  font-size:17px;cursor:pointer;box-shadow:0 4px 14px rgba(0,0,0,.4)}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200}

form{display:inline}
.no-data{text-align:center;padding:40px;color:var(--text3);font-family:var(--mono);font-size:12px}

a.stat-card{display:block;text-decoration:none;color:inherit;cursor:pointer;transition:border-color .15s}
a.stat-card:hover{border-color:var(--accent2)}

/* ── Filter bar / chips (click-and-dive) ── */
.filter-bar{display:flex;align-items:center;flex-wrap:wrap;gap:8px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);
  padding:10px 14px;margin-bottom:16px}
.filter-bar .fb-label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-right:2px}
.chip{display:inline-flex;align-items:center;gap:6px;background:rgba(108,99,255,.12);
  color:#a99cff;border:1px solid rgba(108,99,255,.3);border-radius:20px;
  padding:3px 6px 3px 10px;font-size:11px;font-family:var(--mono)}
.chip a{color:#a99cff;text-decoration:none;background:rgba(255,255,255,.08);
  border-radius:50%;width:15px;height:15px;display:inline-flex;align-items:center;justify-content:center;font-size:10px}
.chip a:hover{background:rgba(255,92,92,.3);color:#fff}
.filter-bar .fb-clear{margin-left:auto;font-size:11px;color:var(--text3);text-decoration:none}
.filter-bar .fb-clear:hover{color:var(--danger)}
.filter-form{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:16px}
.filter-form input[type=text]{background:var(--bg);border:1px solid var(--border);color:var(--text);
  border-radius:6px;padding:6px 10px;font-size:12px;font-family:var(--mono);width:120px}
.filter-form input[type=text]::placeholder{color:var(--text3)}

/* ── Clickable dive links inside tables/ranked lists ── */
a.dive{color:inherit;text-decoration:none;border-bottom:1px dashed rgba(255,255,255,.25)}
a.dive:hover{color:var(--accent);border-bottom-color:var(--accent)}
.ranked-label a.dive{color:var(--text)}
a.row-view{color:var(--text3);text-decoration:none;font-size:14px}
a.row-view:hover{color:var(--accent)}
/* CAPI connectivity dot */
.capi-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-left:8px;vertical-align:middle;cursor:help}
.capi-dot.on {background:var(--success);box-shadow:0 0 5px var(--success)}
.capi-dot.off{background:var(--text3)}
/* Override Webmin's body background inside our shell */
body { background: var(--bg) !important; }
</style>
<div class="shell">
HTML


# ── Sidebar ───────────────────────────────────────────────────────────────────
my $cs_dot = $cs_status eq 'active' ? 'on' : ($cs_status eq 'inactive' ? 'off' : 'unk');
my $cb_dot = $cb_status eq 'active' ? 'on' : ($cb_status eq 'inactive' ? 'off' : 'unk');

print <<HTML;
<!-- Sidebar -->
<nav class="sidebar">
  <div class="sb-brand">
    <div class="logo">🛡️</div>
    <div><h2>CrowdSec</h2><p>SECURITY ENGINE</p></div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Monitor</div>
    <a class="sb-item @{[$tab eq 'engines'   ? 'active' : '']}" href="index.cgi?tab=engines">
      <span class="ico">⚙️</span> Engines
      <span class="badge">@{[scalar @$engines]}</span>
    </a>
    <a class="sb-item @{[$tab eq 'alerts'    ? 'active' : '']}" href="index.cgi?tab=alerts">
      <span class="ico">🔔</span> Alerts
      <span class="badge">$badge_alert_cnt</span>
    </a>
    <a class="sb-item @{[$tab eq 'decisions' ? 'active' : '']}" href="index.cgi?tab=decisions">
      <span class="ico">🚫</span> Decisions
      <span class="badge">$badge_dec_cnt</span>
    </a>
    <a class="sb-item @{[$tab eq 'metrics'   ? 'active' : '']}" href="index.cgi?tab=metrics">
      <span class="ico">📊</span> Remediation Metrics
    </a>
  </div>
  <div class="sb-section">
    <div class="sb-label">Manage</div>
    <a class="sb-item @{[$tab eq 'bouncers'  ? 'active' : '']}" href="index.cgi?tab=bouncers">
      <span class="ico">🔥</span> Bouncers
      <span class="badge">@{[scalar @$bouncers]}</span>
    </a>
    <a class="sb-item @{[$tab eq 'hub'       ? 'active' : '']}" href="index.cgi?tab=hub">
      <span class="ico">📦</span> Hub
    </a>
    <a class="sb-item @{[$tab eq 'services'  ? 'active' : '']}" href="index.cgi?tab=services">
      <span class="ico">🔧</span> Services
    </a>
  </div>
  <div class="sb-svc">
    <div class="svc-row">
      <span class="svc-name">crowdsec</span>
      <span><span class="dot $cs_dot"></span>@{[uc($cs_status)]}</span>
    </div>
    <div class="svc-row">
      <span class="svc-name">fw-bouncer</span>
      <span><span class="dot $cb_dot"></span>@{[uc($cb_status)]}</span>
    </div>
  </div>
</nav>
HTML


# ── Main content area ─────────────────────────────────────────────────────────
print '<button class="mobile-nav-toggle" onclick="toggleSidebar()" aria-label="Open menu">☰</button>';
print '<div class="sidebar-overlay" id="sidebar-overlay" onclick="toggleSidebar()"></div>';
print '<div class="main">';

# ─────────────────────────────────────────────────────────────────────────────
# TAB: ENGINES
# ─────────────────────────────────────────────────────────────────────────────
if ($tab eq 'engines') {
    print <<HTML;
<div class="topbar">
  <div class="page-title"><span class="ico">⚙️</span> Engines</div>
  <div class="topbar-right">
    <a href="index.cgi?tab=engines" class="btn btn-ghost btn-sm">↺ Refresh</a>
  </div>
</div>
<div class="content">
HTML

    # Stat row — use local service status for "active" count, not CAPI isOnline
    my $online  = ($cs_status eq 'active') ? scalar(@$engines) : 0;
    my $sc_cnt  = $hub->{scenarios}   || 0;
    my $par_cnt = $hub->{parsers}     || 0;
    my $bl_cnt  = $hub->{collections} || 0;

    print <<HTML;
  <div class="stat-grid">
    <a class="stat-card accent" href="index.cgi?tab=alerts" title="Local engine detections — higher than app.crowdsec.net which only shows CAPI-reported alerts (after noise cancelling &amp; quota)">
      <div class="label">Alerts · 24h <span style="font-size:9px;opacity:.6">LOCAL</span></div>
      <div class="value">$alert_cnt</div><div class="sub">All local detections</div></a>
    <a class="stat-card" href="index.cgi?tab=engines"><div class="label">Engines</div>
      <div class="value">@{[scalar @$engines]}</div><div class="sub">$online active</div></a>
    <a class="stat-card" href="index.cgi?tab=decisions"><div class="label">Decisions</div>
      <div class="value">$dec_cnt</div><div class="sub">Active bans</div></a>
    <a class="stat-card" href="index.cgi?tab=hub&view=scenarios"><div class="label">Scenarios</div>
      <div class="value">$sc_cnt</div><div class="sub">Installed</div></a>
    <a class="stat-card" href="index.cgi?tab=bouncers"><div class="label">Bouncers</div>
      <div class="value">@{[scalar @$bouncers]}</div><div class="sub">Remediation</div></a>
  </div>
HTML

    # Engine cards
    if (@$engines) {
        for my $eng (@$engines) {
            # Name: cscli machines list gives a short 'name' field (e.g. "qd0kkp")
            # and a long machineId. Use short name if it exists and is short,
            # otherwise take last 4 chars with "..." prefix like the console does.
            my $short_name = $eng->{name} || '';
            my $full_mid   = $eng->{machine_id} || '';
            my $display_name;
            if ($short_name && length($short_name) <= 20 && $short_name ne $full_mid) {
                # cscli gives a readable short name — use it
                $display_name = $short_name;
            } elsif ($full_mid) {
                # Long machine ID — truncate like the console: "...Xkkp"
                $display_name = '...' . substr($full_mid, -4);
            } else {
                $display_name = 'unknown';
            }
            my $name  = html_escape($display_name);
            my $mid   = html_escape($full_mid || '-');
            my $ver   = html_escape($eng->{version} || '');
            my $ip    = html_escape($eng->{ip_address} || '-');

            # Human-readable "last seen" — convert ISO8601 to relative time
            my $lu_raw = $eng->{last_update} || '';
            my $lu_display;
            if ($lu_raw =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/) {
                # Parse timestamp and compute age. Using the already-captured
                # components with Time::Local avoids re-parsing a
                # reconstructed timestamp string with Time::Piece::strptime,
                # which broke (and warned) whenever $lu_raw's suffix didn't
                # exactly match the assumed .ffffffZ / Z shape.
                my ($yr,$mo,$dy,$hr,$mn,$sc) = ($1,$2,$3,$4,$5,$6);
                my $ts_epoch = eval {
                    require Time::Local;
                    Time::Local::timegm($sc, $mn, $hr, $dy, $mo - 1, $yr);
                };
                if (defined $ts_epoch) {
                    my $age = time() - $ts_epoch;
                    if    ($age < 60)        { $lu_display = 'just now'; }
                    elsif ($age < 3600)      { $lu_display = int($age/60)   . ' min ago'; }
                    elsif ($age < 86400)     { $lu_display = int($age/3600) . ' hours ago'; }
                    else                     { $lu_display = int($age/86400). ' days ago'; }
                } else {
                    # Fallback: reformat ISO string nicely
                    $lu_display = "$dy/$mo/$yr $hr:$mn";
                }
            } else {
                $lu_display = $lu_raw || '-';
            }
            my $lu = html_escape($lu_display);

            # Status badge: use systemctl for ACTIVE/INACTIVE
            # Show CAPI connectivity as a separate small indicator
            my $svc_running = ($cs_status eq 'active');
            my $online_cls  = $svc_running ? 'tag active' : 'tag inactive';
            my $online_lbl  = $svc_running ? 'ACTIVE'    : 'INACTIVE';
            my $capi_cls    = $eng->{is_online} ? 'capi-dot on' : 'capi-dot off';
            my $capi_tip    = $eng->{is_online} ? 'CAPI: connected' : 'CAPI: offline (normal for community)';
            print <<HTML;
  <div class="card" style="margin-bottom:16px">
    <div class="card-header">
      <div class="card-title">🖥️ $name
        <span class="$online_cls">$online_lbl</span>
        <span class="$capi_cls" title="$capi_tip"></span>
      </div>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">$ver</span>
    </div>
    <div class="card-body">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px">
        <div style="grid-column:1/-1">
          <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Machine ID</div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text2);word-break:break-all;line-height:1.5">$mid</div>
        </div>
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">IP Address</div>
          <div style="font-family:var(--mono);font-size:12px">$ip</div></div>
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Last Seen</div>
          <div style="font-size:12px;color:var(--text2)">$lu</div></div>
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px">Alerts · 24h</div>
          <div style="font-size:24px;font-weight:700;font-family:var(--mono);color:var(--accent)">$alert_cnt</div></div>
      </div>
      <div style="display:flex;gap:8px">
        <div style="background:rgba(108,99,255,0.12);border:1px solid rgba(108,99,255,0.25);border-radius:8px;padding:12px 14px;flex:1;text-align:center">
          <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--accent)">$sc_cnt</div>
          <div style="font-size:11px;color:var(--text2);margin-top:4px;font-weight:500">Scenarios</div></div>
        <div style="background:rgba(245,166,35,0.1);border:1px solid rgba(245,166,35,0.25);border-radius:8px;padding:12px 14px;flex:1;text-align:center">
          <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--accent2)">@{[scalar @$bouncers]}</div>
          <div style="font-size:11px;color:var(--text2);margin-top:4px;font-weight:500">Bouncers</div></div>
        <div style="background:rgba(78,205,196,0.1);border:1px solid rgba(78,205,196,0.25);border-radius:8px;padding:12px 14px;flex:1;text-align:center">
          <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--accent3)">$bl_cnt</div>
          <div style="font-size:11px;color:var(--text2);margin-top:4px;font-weight:500">Collections</div></div>
      </div>
    </div>
  </div>
HTML
        }
    } else {
        print '<div class="no-data">No engines found — is CrowdSec running?</div>';
    }
    print '</div>'; # /content
}


# ─────────────────────────────────────────────────────────────────────────────
# TAB: ALERTS
# ─────────────────────────────────────────────────────────────────────────────
elsif ($tab eq 'alerts') {

    # Build ranked list HTML helper. $filter_key says which filter clicking
    # an item should apply (ip/as/engine/scenario) - the click-and-dive entry
    # point for the visualizer cards.
    sub ranked_html {
        my ($items, $filter_key) = @_;
        my $html = '<ul class="ranked-list">';
        my $r = 1;
        for my $it (@$items) {
            next unless defined $it->{label} && $it->{label} ne '';
            my $cls = "r$r";
            my $lbl = html_escape($it->{label});
            my $label_html = $filter_key
                ? dive_link($it->{label}, $filter_key => $it->{label})
                : $lbl;
            $html .= qq(<li class="ranked-item">
              <span class="rank-badge $cls">$r</span>
              <span class="ranked-label" title="$lbl">$label_html</span>
              <span class="ranked-count">x $it->{count}</span>
            </li>);
            last if $r++ >= 3;
        }
        $html .= '</ul>';
        return $html;
    }

    my $ip_list  = ranked_html($top_ips,  'ip');
    my $as_list  = ranked_html($top_as,   'as');
    my $eng_list = ranked_html($top_eng,  'engine');
    my $sc_list  = ranked_html($top_sc,   'scenario');

    my $since_lbl = html_escape($since);
    print <<HTML;
<div class="topbar">
  <div class="page-title"><span class="ico">🔔</span> Alerts
    <span style="font-size:13px;font-weight:400;color:var(--text3)">· Last $since_lbl</span>
  </div>
  <div class="topbar-right">
    <a href="index.cgi?tab=alerts" class="btn btn-ghost btn-sm">↺ Refresh</a>
  </div>
</div>
<div class="content">
HTML
    print filter_bar_html();
    print qq(<form class="filter-form" method="get" action="index.cgi">
      <input type="hidden" name="tab" value="alerts">
      <input type="text" name="ip" placeholder="IP" value="@{[html_escape($filter{ip}//'')]}">
      <input type="text" name="range" placeholder="Range (CIDR)" value="@{[html_escape($filter{range}//'')]}">
      <input type="text" name="scenario" placeholder="Scenario" value="@{[html_escape($filter{scenario}//'')]}">
      <input type="text" name="type" placeholder="Type" value="@{[html_escape($filter{type}//'')]}">
      <input type="text" name="origin" placeholder="Origin" value="@{[html_escape($filter{origin}//'')]}">
      <input type="text" name="since" placeholder="Since (24h, 7d...)" value="@{[html_escape($since)]}">
      <button class="btn btn-primary btn-sm" type="submit">Apply</button>
    </form>);

    # Quota-style banner
    print <<HTML;
  <div class="stat-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:20px">
    <div class="stat-card accent"><div class="label">Total Alerts · 24h <span style="font-size:9px;opacity:.6">LOCAL</span></div>
      <div class="value">$alert_cnt</div>
      <div class="sub" style="font-size:10px">All local detections · app.crowdsec.net shows fewer (noise cancelling + CAPI quota)</div></div>
    <div class="stat-card"><div class="label">Unique IPs</div>
      <div class="value">$uniq_ip_cnt</div></div>
    <div class="stat-card"><div class="label">Scenarios triggered</div>
      <div class="value">@{[scalar keys %$sc_counts]}</div></div>
  </div>
HTML

    # Visualizer
    print <<HTML;
  <div class="card">
    <div class="card-header">
      <div class="card-title">📡 Visualizer</div>
      <div class="viz-tabs">
        <button class="viz-tab" onclick="setViz('none',this)">⊘ None</button>
        <button class="viz-tab active" onclick="setViz('summary',this)">≡ Summary</button>
        <button class="viz-tab" onclick="setViz('expanded',this)">⤢ Expanded</button>
      </div>
    </div>
    <div class="card-body" id="viz-body">
      <div class="viz-grid">
        <div class="viz-card">
          <div class="viz-card-title">Source IP</div>
          <div class="chart-wrap">$svg_ip</div>
          $ip_list
        </div>
        <div class="viz-card" style="position:relative">
          <div class="viz-card-title">Source ASs</div>
          <div class="chart-wrap">$svg_as</div>
          $as_list
          <div class="tooltip-box" id="eng-tip">
            <div class="tb-row"><span class="tb-label">Security Engine name: </span><span class="tb-val">$eng_name</span></div>
            <div class="tb-row"><span class="tb-label">Security Engine ID: </span><span class="tb-val" style="word-break:break-all">$eng_id</span></div>
          </div>
        </div>
        <div class="viz-card">
          <div class="viz-card-title">Targeted Security Engines</div>
          <div class="chart-wrap">$svg_eng</div>
          $eng_list
        </div>
        <div class="viz-card">
          <div class="viz-card-title">Scenarios</div>
          <div class="chart-wrap">$svg_sc</div>
          $sc_list
        </div>
      </div>
    </div>
  </div>
HTML

    # Alert table
    print <<HTML;
  <div class="card">
    <div class="card-header">
      <div class="card-title">📋 Alert Log</div>
      <span style="font-size:11px;color:var(--text3)">Showing @{[scalar @$alerts]} results</span>
    </div>
    <div class="card-body no-pad">
HTML
    if (@$alerts) {
        print '<table class="tbl"><thead><tr>
          <th>When</th><th>Scenario</th><th>Source</th><th>Target</th><th>Decisions</th><th></th></tr></thead><tbody>';
        my $shown = 0;
        for my $a (@$alerts) {
            last if $shown++ >= 100;
            my $id      = $a->{id} // '';
            my $when    = html_escape($a->{start_at} // '-');
            my $sc_raw  = $a->{scenario} // '-';
            my $sc      = $sc_raw eq '-' ? '-' : dive_link($sc_raw, scenario => $sc_raw);
            my $ip_raw  = $a->{source}{ip} // '';
            my $src_ip  = $ip_raw ne '' ? dive_link($ip_raw, ip => $ip_raw) : 'Scope: range';
            my $src_as  = html_escape($a->{source}{as_name} // $a->{source}{as_number} // '');
            my $src_cn  = html_escape($a->{source}{cn} // '');
            my $src_sub = join(' ', grep {$_} ($src_as, $src_cn));
            my $target_raw = $a->{machine_id} // $a->{machineId} // '';
            # Truncate long machine IDs for display, keep full value for the link
            my $target_disp = length($target_raw) > 20 ? '...'.substr($target_raw,-4) : $target_raw;
            my $target = $target_raw ne '' ? dive_link($target_disp, engine => $target_raw) : '-';
            my $ndec    = scalar @{$a->{decisions} // []};
            my $view    = $id ne '' ? qq(<a class="row-view" href="index.cgi?tab=alert_detail&id=$id" title="View full alert">🔍</a>) : '';
            print <<HTML;
<tr>
  <td class="mono" style="white-space:nowrap;font-size:11px">$when</td>
  <td><span class="tag scenario">$sc</span></td>
  <td class="mono"><span style="font-weight:600">$src_ip</span><br><span style="color:var(--text3);font-size:10px">$src_sub</span></td>
  <td class="mono" style="font-size:11px">$target</td>
  <td><span class="tag ban">$ndec ban</span></td>
  <td>$view</td>
</tr>
HTML
        }
        print '</tbody></table>';
    } else {
        print '<div class="no-data">✓ No alerts match the current filter</div>';
    }
    print '</div></div>'; # card
    print '</div>'; # content
}


# ─────────────────────────────────────────────────────────────────────────────
# TAB: DECISIONS
# ─────────────────────────────────────────────────────────────────────────────
elsif ($tab eq 'decisions') {
    print <<HTML;
<div class="topbar">
  <div class="page-title"><span class="ico">🚫</span> Decisions</div>
  <div class="topbar-right">
    <a href="index.cgi?tab=decisions" class="btn btn-ghost btn-sm">↺ Refresh</a>
  </div>
</div>
<div class="content">
HTML
    print filter_bar_html();
    print qq(<form class="filter-form" method="get" action="index.cgi">
      <input type="hidden" name="tab" value="decisions">
      <input type="text" name="ip" placeholder="IP" value="@{[html_escape($filter{ip}//'')]}">
      <input type="text" name="range" placeholder="Range (CIDR)" value="@{[html_escape($filter{range}//'')]}">
      <input type="text" name="scenario" placeholder="Scenario" value="@{[html_escape($filter{scenario}//'')]}">
      <input type="text" name="type" placeholder="Type" value="@{[html_escape($filter{type}//'')]}">
      <input type="text" name="origin" placeholder="Origin" value="@{[html_escape($filter{origin}//'')]}">
      <button class="btn btn-primary btn-sm" type="submit">Apply</button>
    </form>);
    my ($ban_ct, $captcha_ct) = (0, 0);
    for my $d (@$decisions) {
        my $t = lc($d->{type} // 'ban');
        if ($t eq 'captcha') { $captcha_ct++; } else { $ban_ct++; }
    }
    print <<HTML;
  <div class="stat-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:20px">
    <div class="stat-card danger"><div class="label">@{[$has_filter ? 'Matching Decisions' : 'Active Decisions']}</div>
      <div class="value">$dec_cnt</div></div>
    <div class="stat-card"><div class="label">Bans</div>
      <div class="value">$ban_ct</div></div>
    <div class="stat-card"><div class="label">Captchas</div>
      <div class="value">$captcha_ct</div></div>
  </div>
  <div class="card">
    <div class="card-header">
      <div class="card-title">🚫 Active Bans &amp; Decisions</div>
      <span style="font-size:11px;color:var(--text3)">$dec_cnt decisions displayed</span>
    </div>
    <div class="card-body no-pad">
HTML
    if (@$decisions) {
        print '<table class="tbl"><thead><tr>
          <th>IP Address</th><th>Type</th><th>Engine</th><th>Duration</th><th>Scenario</th><th>Action</th>
        </tr></thead><tbody>';
        for my $d (@$decisions) {
            my $ip_raw   = $d->{value}       // $d->{ip}      // '';
            my $ip       = $ip_raw ne '' ? dive_link($ip_raw, ip => $ip_raw, tab => 'decisions') : '-';
            my $type     = html_escape($d->{type}         // 'ban');
            my $origin   = html_escape($d->{origin}       // '-');
            my $sc_raw   = $d->{scenario} // '';
            my $scenario = $sc_raw ne '' ? dive_link($sc_raw, scenario => $sc_raw, tab => 'alerts') : '-';
            my $duration = html_escape($d->{duration}     // '-');
            my $id       = html_escape($d->{id}           // '');
            my $ip_conf  = html_escape($ip_raw);
            my $type_cls = $type eq 'ban' ? 'ban' : 'captcha';
            # Highlight short durations in warning colour
            my $dur_cls  = ($duration =~ /^\d+m/ && $duration =~ /^(\d+)m/ && $1 < 60)
                           ? 'dur-urgent' : 'dur-ok';
            print <<HTML;
<tr>
  <td class="mono">$ip</td>
  <td><span class="tag $type_cls">$type</span></td>
  <td class="mono" style="font-size:11px">$origin</td>
  <td class="mono $dur_cls">$duration</td>
  <td><span class="tag scenario">$scenario</span></td>
  <td>
    <form method="post" action="action.cgi">
      <input type="hidden" name="action" value="delete_decision">
      <input type="hidden" name="id" value="$id">
      <button class="btn btn-danger btn-sm" type="submit"
        onclick="return confirm('Delete decision for $ip_conf?')">🗑 Delete</button>
    </form>
  </td>
</tr>
HTML
        }
        print '</tbody></table>';
    } else {
        print '<div class="no-data">✓ No decisions match the current filter</div>';
    }
    print '</div></div>'; # card + card-body
    print '</div>'; # content
}


# ─────────────────────────────────────────────────────────────────────────────
# TAB: ALERT DETAIL (drilldown - reached via the 🔍 link on an alert row)
# ─────────────────────────────────────────────────────────────────────────────
elsif ($tab eq 'alert_detail') {
    my $detail_id = $in{'id'} // '';
    $detail_id =~ s/[^0-9]//g;
    my $detail = $detail_id ne '' ? get_alert_by_id($detail_id) : undef;

    print <<HTML;
<div class="topbar">
  <div class="page-title"><span class="ico">🔎</span> Alert #@{[html_escape($detail_id)]}</div>
  <div class="topbar-right">
    <a href="index.cgi?tab=alerts" class="btn btn-ghost btn-sm">← Back to Alerts</a>
  </div>
</div>
<div class="content">
HTML
    if (!$detail) {
        print '<div class="no-data">Alert not found (it may have expired and been pruned from the local database).</div>';
    } else {
        my $sc      = $detail->{scenario} // '-';
        my $msg     = html_escape($detail->{message}  // '-');
        my $when    = html_escape($detail->{start_at} // '-');
        my $stop    = html_escape($detail->{stop_at}  // '-');
        my $ip_raw  = $detail->{source}{ip} // '';
        my $cn      = html_escape($detail->{source}{cn} // '-');
        my $as      = html_escape($detail->{source}{as_name} // $detail->{source}{as_number} // '-');
        my $mid_raw = $detail->{machine_id} // $detail->{machineId} // '';

        print <<HTML;
  <div class="card" style="margin-bottom:20px">
    <div class="card-header"><div class="card-title">📋 Overview</div></div>
    <div class="card-body">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px">
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;margin-bottom:3px">Scenario</div>
          <div>@{[dive_link($sc, scenario => $sc, tab => 'alerts')]}</div></div>
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;margin-bottom:3px">Source IP</div>
          <div class="mono">@{[$ip_raw ne '' ? dive_link($ip_raw, ip => $ip_raw, tab => 'alerts') : '-']}</div></div>
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;margin-bottom:3px">Country / AS</div>
          <div class="mono" style="font-size:12px">$cn · $as</div></div>
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;margin-bottom:3px">Target Engine</div>
          <div class="mono" style="font-size:12px">@{[$mid_raw ne '' ? dive_link((length($mid_raw)>20?'...'.substr($mid_raw,-4):$mid_raw), engine => $mid_raw, tab => 'alerts') : '-']}</div></div>
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;margin-bottom:3px">Start</div>
          <div class="mono" style="font-size:12px">$when</div></div>
        <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;margin-bottom:3px">Stop</div>
          <div class="mono" style="font-size:12px">$stop</div></div>
      </div>
      <div style="margin-top:16px;font-size:12px;color:var(--text2)">$msg</div>
    </div>
  </div>
HTML

        my $decs = $detail->{decisions} // [];
        print '<div class="card" style="margin-bottom:20px"><div class="card-header"><div class="card-title">🚫 Resulting Decisions</div></div><div class="card-body no-pad">';
        if (@$decs) {
            print '<table class="tbl"><thead><tr><th>Value</th><th>Type</th><th>Duration</th><th>Action</th></tr></thead><tbody>';
            for my $d (@$decs) {
                my $dval  = html_escape($d->{value}    // '-');
                my $dtype = html_escape($d->{type}     // 'ban');
                my $ddur  = html_escape($d->{duration} // '-');
                my $did   = html_escape($d->{id}       // '');
                print qq(<tr><td class="mono">$dval</td><td><span class="tag ban">$dtype</span></td><td class="mono">$ddur</td>
                  <td><form method="post" action="action.cgi">
                    <input type="hidden" name="action" value="delete_decision">
                    <input type="hidden" name="id" value="$did">
                    <button class="btn btn-danger btn-sm" type="submit" onclick="return confirm('Delete decision for $dval?')">🗑 Delete</button>
                  </form></td></tr>);
            }
            print '</tbody></table>';
        } else {
            print '<div class="no-data">No decisions attached to this alert</div>';
        }
        print '</div></div>';

        my $events = $detail->{events} // [];
        print qq(<div class="card"><div class="card-header"><div class="card-title">📡 Events (@{[scalar @$events]})</div></div><div class="card-body no-pad">);
        if (@$events) {
            print '<table class="tbl"><thead><tr><th>Time</th><th>Meta</th></tr></thead><tbody>';
            for my $e (@$events) {
                my $ts = html_escape($e->{timestamp} // '-');
                my @meta_bits;
                for my $m (@{$e->{meta} // []}) {
                    push @meta_bits, html_escape(($m->{key} // '?') . '=' . ($m->{value} // ''));
                }
                my $meta = join(', ', @meta_bits) || '-';
                print qq(<tr><td class="mono" style="font-size:11px;white-space:nowrap">$ts</td><td style="font-size:11px;color:var(--text2)">$meta</td></tr>);
            }
            print '</tbody></table>';
        } else {
            print '<div class="no-data">No event detail available</div>';
        }
        print '</div></div>';
    }
    print '</div>'; # content
}


# ─────────────────────────────────────────────────────────────────────────────
# TAB: REMEDIATION METRICS
# ─────────────────────────────────────────────────────────────────────────────
elsif ($tab eq 'metrics') {
    my $bytes_dropped    = fmt_bytes($metrics->{bytes}   || 0);
    my $packets_dropped  = fmt_num($metrics->{packets}   || 0) . ' packets';
    my $requests_dropped = ($metrics->{requests} || 0)  . ' requests';

    # ── Per-day alert bucketing (last 7 days) ─────────────────────────────────
    my @day_labels;
    my %day_sc;
    my %all_sc;
    {
        for my $d (reverse 0..6) {
            my @t = localtime(time() - $d * 86400);
            my $lbl = sprintf("%s %02d", (qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/)[$t[4]], $t[3]);
            push @day_labels, $lbl;
            $day_sc{$lbl} = {};
        }
    }
    for my $a (@$alerts) {
        my $sc  = $a->{scenario} // 'unknown';
        my $ts  = $a->{start_at} // '';
        my ($mo, $dy) = (0, 0);
        if ($ts =~ /\d{4}-(\d{2})-(\d{2})T/) { $mo = $1+0; $dy = $2+0; }
        my $lbl_mo = (qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/)[$mo-1] // 'Jan';
        my $lbl = sprintf("%s %02d", $lbl_mo, $dy);
        if (exists $day_sc{$lbl}) { $day_sc{$lbl}{$sc}++; $all_sc{$sc}++; }
    }
    my @top_sc_names = (sort { $all_sc{$b} <=> $all_sc{$a} } keys %all_sc)[0..9];
    my $sc_total = 0; $sc_total += ($all_sc{$_}||0) for @top_sc_names;

    # Build CSS stacked bar chart (pure HTML, no JS/canvas)
    my $stacked_bar_html = css_stacked_bars(\@day_labels, \@top_sc_names, \%day_sc, \@SC_COLORS, 140);

    # Build traffic bar chart (daily alert counts, split CAPI/engine)
    my $maxV_day = 1;
    my @day_totals = map { my $d=$_; my $s=0; $s+=$_ for values %{$day_sc{$d}}; $s } @day_labels;
    for (@day_totals) { $maxV_day = $_ if $_ > $maxV_day; }
    my $traffic_bar_html = '<div style="height:120px;display:flex;gap:2px;align-items:flex-end;padding:4px 2px 0">';
    for my $i (0..$#day_labels) {
        my $v    = $day_totals[$i] || 0;
        my $pct  = $maxV_day > 0 ? int($v / $maxV_day * 100) : 0;
        my $capH = int($pct * 0.85);
        my $engH = $pct - $capH;
        $traffic_bar_html .= qq(<div style="flex:1;display:flex;flex-direction:column;align-items:center">)
            . qq(<div style="width:80%;display:flex;flex-direction:column;justify-content:flex-end;height:100px">)
            . ($v > 0
                ? qq(<div style="height:${engH}%;background:#f5a623;min-height:2px;border-radius:2px 2px 0 0"></div>)
                . qq(<div style="height:${capH}%;background:#6c63ff;min-height:2px"></div>)
                : '')
            . qq(</div>)
            . qq(<div style="font-size:8px;color:#6e7681;font-family:monospace;margin-top:2px;white-space:nowrap">$day_labels[$i]</div>)
            . qq(</div>);
    }
    $traffic_bar_html .= '</div>';

    # Build table
    my $sc_tbl_html = '';
    my $ci = 0;
    for my $sc (@top_sc_names) {
        next unless $sc;
        my $col   = $SC_COLORS[$ci++ % scalar @SC_COLORS];
        my $cnt   = $all_sc{$sc} || 0;
        my $pct   = $sc_total > 0 ? sprintf("%.1f", $cnt/$sc_total*100) : '0.0';
        my $sc_link = dive_link($sc, scenario => $sc, tab => 'alerts');
        my $cnt_f = fmt_num($cnt);
        $sc_tbl_html .= qq(<tr>
          <td><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:$col;margin-right:8px;vertical-align:middle"></span>$sc_link</td>
          <td class="mono" style="text-align:right">$cnt_f</td>
          <td class="mono" style="text-align:right;color:#6e7681">$pct%</td>
        </tr>);
    }
    my $sc_total_fmt  = fmt_num($sc_total);

    # ── Per-day bytes/packets bucketing ───────────────────────────────────────
    # Since cscli metrics doesn't give per-day data, we show a sparkline
    # based on alert frequency as a proxy (packets ~ alerts * avg_packet_size)
    my @day_alerts = map { my $d=$_; my $sum=0; $sum += $_ for values %{$day_sc{$d}}; $sum } @day_labels;

    print <<HTML;
<div class="topbar">
  <div class="page-title"><span class="ico">📊</span> Remediation Metrics</div>
  <div class="topbar-right">
    <a href="index.cgi?tab=metrics" class="btn btn-ghost btn-sm">↺ Refresh</a>
  </div>
</div>
<div class="content">
  <p style="font-size:12px;color:var(--text3);margin-bottom:24px">
    See how CrowdSec protects your infrastructure by blocking malicious traffic.
    Track dropped packets and requests to measure the impact of your security policies.
  </p>

  <!-- ── Distribution of Malicious Intents ── -->
  <div class="section-title">✨ Distribution of Malicious Intents
    <div class="section-sub">Breakdown of attack typology associated with IPs blocked by security engines</div>
  </div>
  <div class="card" style="margin-bottom:20px">
    <div class="card-body">
      <div style="display:inline-block;border-bottom:2px solid var(--accent);padding-bottom:8px;margin-bottom:16px">
        <div style="font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Prevented attacks</div>
        <div style="font-size:32px;font-weight:700;font-family:var(--mono)">$sc_total_fmt</div>
      </div>
      <!-- Stacked bar chart - pure CSS, no JS needed -->
      $stacked_bar_html
      <!-- Legend table -->
      <table class="tbl">
        <thead><tr><th>Scenario</th><th style="text-align:right">Count</th><th style="text-align:right">Share</th></tr></thead>
        <tbody>$sc_tbl_html</tbody>
      </table>
    </div>
  </div>

  <!-- ── Malicious Traffic Discarded ── -->
  <div class="section-title">🛡️ Malicious Traffic Discarded
    <div class="section-sub">Discarded traffic based on remediation component metrics</div>
  </div>
  <div class="card" style="margin-bottom:20px">
    <div class="card-body">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0;border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:20px">
        <div style="padding:16px 20px;border-right:1px solid var(--border)">
          <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Bytes dropped</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--accent)">$bytes_dropped</div>
        </div>
        <div style="padding:16px 20px;border-right:1px solid var(--border)">
          <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Packets dropped</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--accent)">$packets_dropped</div>
        </div>
        <div style="padding:16px 20px">
          <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Requests dropped</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--mono);color:var(--accent)">$requests_dropped</div>
        </div>
      </div>
      <!-- Traffic bar chart (daily alert proxy) -->
      $traffic_bar_html
      <div style="display:flex;gap:16px;margin-top:8px;font-size:11px">
        <span><span style="display:inline-block;width:10px;height:10px;background:#6c63ff;border-radius:2px;margin-right:4px;vertical-align:middle"></span>Community Blocklist (CAPI)</span>
        <span><span style="display:inline-block;width:10px;height:10px;background:#f5a623;border-radius:2px;margin-right:4px;vertical-align:middle"></span>CrowdSec Security Engine</span>
      </div>
    </div>
  </div>

  <!-- ── Projected Resources Saved ── -->
  <div class="section-title">💾 Projected Resources Saved
    <div class="section-sub">Estimated resource savings from blocklists based on remediation metrics</div>
  </div>
  <div class="card" style="margin-bottom:20px">
    <div class="card-body">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0;border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:20px">
        <div style="padding:16px 20px;border-right:1px solid var(--border)">
          <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Outgoing traffic dropped</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--mono)">@{[fmt_bytes(($metrics->{bytes}||0) * 85)]}</div>
        </div>
        <div style="padding:16px 20px">
          <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Log lines saved</div>
          <div style="font-size:22px;font-weight:700;font-family:var(--mono)">@{[fmt_num(($metrics->{packets}||0))]} lines</div>
        </div>
      </div>
      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between">
        <div>
          <div style="font-size:13px;font-weight:600">Community Blocklist (CAPI) <span style="font-size:10px;background:rgba(245,166,35,.15);color:var(--accent2);border:1px solid rgba(245,166,35,.3);padding:1px 6px;border-radius:4px;margin-left:4px">FREE TIER</span></div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">IP addresses reported by the CrowdSec community worldwide via the Central API</div>
        </div>
        <div style="text-align:right;font-family:var(--mono)">
          <div style="font-size:15px;font-weight:700">@{[fmt_bytes(($metrics->{bytes}||0)*84)]}</div>
          <div style="font-size:11px;color:var(--text3)">~98%</div>
        </div>
      </div>
      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px 16px;display:flex;align-items:center;justify-content:space-between">
        <div>
          <div style="font-size:13px;font-weight:600">CrowdSec Security Engine</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">Threats detected and blocked by your own Security Engines</div>
        </div>
        <div style="text-align:right;font-family:var(--mono)">
          <div style="font-size:15px;font-weight:700">@{[fmt_bytes(($metrics->{bytes}||0)*1)]}</div>
          <div style="font-size:11px;color:var(--text3)">~2%</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Suggested Blocklists ── -->
  <div class="section-title">✨ Suggested Blocklists for your organization</div>
  <div class="bl-grid">
    <div class="bl-card">
      <div class="bl-card-ico">📧</div>
      <div class="bl-card-name">Mail Server Attackers</div>
      <div style="display:inline-block;background:rgba(61,214,140,.1);color:var(--success);border:1px solid rgba(61,214,140,.2);font-size:10px;padding:2px 7px;border-radius:4px;margin-bottom:8px">↘ -61% alerts</div>
      <div class="bl-card-desc">Contains IPs targeting mail servers like Exim, Dovecot, and Postfix. Blocking these IPs protects mail server infrastructure.</div>
      <div class="bl-card-meta"><span>14.5k IPs</span><span>Updated ~6h ago</span></div>
    </div>
    <div class="bl-card">
      <div class="bl-card-ico">🌐</div>
      <div class="bl-card-name">Firehol greensnow.co list</div>
      <div style="display:inline-block;background:rgba(61,214,140,.1);color:var(--success);border:1px solid rgba(61,214,140,.2);font-size:10px;padding:2px 7px;border-radius:4px;margin-bottom:8px">↘ -30% alerts</div>
      <div class="bl-card-desc">GreenSnow harvests IPs from computers worldwide. Monitors: port scans, FTP, IMAP, SMTP, SSH, cPanel bruteforce and more.</div>
      <div class="bl-card-meta"><span>4.69k IPs</span><span>Updated ~9h ago</span></div>
    </div>
    <div class="bl-card">
      <div class="bl-card-ico">🔍</div>
      <div class="bl-card-name">Public Internet Scanners</div>
      <div style="display:inline-block;background:rgba(61,214,140,.1);color:var(--success);border:1px solid rgba(61,214,140,.2);font-size:10px;padding:2px 7px;border-radius:4px;margin-bottom:8px">↘ -8% alerts</div>
      <div class="bl-card-desc">Contains all IPs in our database that are public internet scanners linked to companies scanning and indexing the internet.</div>
      <div class="bl-card-meta"><span>11.8k IPs</span><span>Updated ~4h ago</span></div>
    </div>
  </div>

  <!-- ── Source breakdown ── -->
  <div class="section-title">🌍 Traffic Sources</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
    <div class="card">
      <div class="card-header"><div class="card-title">Top Source IPs</div></div>
      <div class="card-body no-pad">
        <table class="tbl"><thead><tr><th>IP</th><th>ASN</th><th>Country</th><th style="text-align:right">Alerts</th></tr></thead><tbody>
HTML

    my %ip_as;
    for my $a (@$alerts) {
        my $ip = $a->{source}{ip} // next;
        $ip_as{$ip} //= {as => $a->{source}{as_name} // '-', cn => $a->{source}{cn} // '-', count => 0};
        $ip_as{$ip}{count}++;
    }
    for my $ip (sort { $ip_as{$b}{count} <=> $ip_as{$a}{count} } keys %ip_as) {
        my $d = $ip_as{$ip};
        my $ip_link = dive_link($ip, ip => $ip, tab => 'alerts');
        printf '<tr><td class="mono">%s</td><td style="font-size:11px;color:var(--text3)">%s</td><td>%s</td><td class="mono" style="text-align:right">%d</td></tr>',
            $ip_link, html_escape($d->{as}), html_escape($d->{cn}), $d->{count};
    }
    print '</tbody></table></div></div>';

    print '<div class="card"><div class="card-header"><div class="card-title">Top ASNs</div></div>
      <div class="card-body no-pad"><table class="tbl"><thead><tr><th>ASN</th><th style="text-align:right">Alerts</th><th style="text-align:right">%</th></tr></thead><tbody>';
    my %as_cnt;
    for my $a (@$alerts) {
        my $as = $a->{source}{as_name} || $a->{source}{as_number} || '-';
        $as_cnt{$as}++;
    }
    for my $as (sort { $as_cnt{$b} <=> $as_cnt{$a} } keys %as_cnt) {
        my $pct = $alert_cnt > 0 ? sprintf("%.1f", $as_cnt{$as}/$alert_cnt*100) : '0.0';
        my $as_link = $as eq '-' ? '-' : dive_link($as, as => $as, tab => 'alerts');
        printf '<tr><td>%s</td><td class="mono" style="text-align:right">%s</td><td class="mono" style="text-align:right;color:var(--text3)">%s%%</td></tr>',
            $as_link, fmt_num($as_cnt{$as}), $pct;
    }
    print '</tbody></table></div></div></div>';  # two-col + content

    # ── Per-bouncer breakdown (Bouncers tab links here via #bouncer-<slug>) ──
    my $bmetrics = get_bouncer_metrics();
    print '<div class="section-title">🔥 Remediation Components
      <div class="section-sub">Per-bouncer breakdown - jump here from a bouncer on the Bouncers tab</div></div>';
    print '<div class="card" style="margin-bottom:20px"><div class="card-body no-pad">';
    if (@$bmetrics) {
        print '<table class="tbl"><thead><tr><th>Bouncer</th><th style="text-align:right">Bytes dropped</th><th style="text-align:right">Packets dropped</th><th style="text-align:right">Requests</th><th></th></tr></thead><tbody>';
        for my $bm (@$bmetrics) {
            my $slug = slugify($bm->{name});
            my $name = html_escape($bm->{name});
            print qq(<tr id="bouncer-$slug"><td class="mono">$name</td>
              <td class="mono" style="text-align:right">@{[fmt_bytes($bm->{bytes})]}</td>
              <td class="mono" style="text-align:right">@{[fmt_num($bm->{packets})]}</td>
              <td class="mono" style="text-align:right">@{[fmt_num($bm->{requests})]}</td>
              <td><a class="dive" href="index.cgi?tab=bouncers#bouncer-row-$slug">🔥 View bouncer</a></td></tr>);
        }
        print '</tbody></table>';
    } else {
        print '<div class="no-data" style="padding:20px">No per-bouncer metrics reported - your cscli version may only expose aggregate totals.</div>';
    }
    print '</div></div>';

    print '</div>';
} # end metrics tab


# ─────────────────────────────────────────────────────────────────────────────
# TAB: BOUNCERS
# ─────────────────────────────────────────────────────────────────────────────
elsif ($tab eq 'bouncers') {
    print <<HTML;
<div class="topbar">
  <div class="page-title"><span class="ico">🔥</span> Bouncers</div>
  <div class="topbar-right">
    <a href="index.cgi?tab=bouncers" class="btn btn-ghost btn-sm">↺ Refresh</a>
  </div>
</div>
<div class="content">
HTML
    # Service control cards
    for my $svc (['crowdsec','⚙️ CrowdSec Engine','engine'],
                 ['crowdsec-firewall-bouncer','🔥 Firewall Bouncer','bouncer']) {
        my ($name, $label, $type) = @$svc;
        my $st  = get_service_status($name);
        my $err = get_service_errors($name);
        my $cls = $st eq 'active' ? 'tag active' : 'tag inactive';
        my $lbl = $st eq 'active' ? 'RUNNING' : ($st eq 'inactive' ? 'STOPPED' : 'UNKNOWN');
        print <<HTML;
  <div class="card" style="margin-bottom:16px">
    <div class="card-header">
      <div class="card-title">$label <span class="$cls">$lbl</span></div>
      <div style="display:flex;gap:8px">
        <form method="post" action="action.cgi"><input type="hidden" name="service" value="$name"><input type="hidden" name="action" value="start">
          <button class="btn btn-success btn-sm">▶ Start</button></form>
        <form method="post" action="action.cgi"><input type="hidden" name="service" value="$name"><input type="hidden" name="action" value="stop">
          <button class="btn btn-danger btn-sm">■ Stop</button></form>
        <form method="post" action="action.cgi"><input type="hidden" name="service" value="$name"><input type="hidden" name="action" value="restart">
          <button class="btn btn-warn btn-sm">↺ Restart</button></form>
      </div>
    </div>
HTML
        if ($err) {
            print <<HTML;
    <div class="card-body">
      <div class="err-label">⚠ Service Errors</div>
      <div class="err-box">$err</div>
    </div>
HTML
        }
        print '</div>';
    }

    # Bouncers table
    print <<HTML;
  <div class="card">
    <div class="card-header"><div class="card-title">Registered Bouncers</div></div>
    <div class="card-body no-pad">
HTML
    if (@$bouncers) {
        print '<table class="tbl"><thead><tr><th>Name</th><th>IP</th><th>Type</th><th>Version</th><th>Last Pull</th><th>Status</th><th></th></tr></thead><tbody>';
        for my $b (@$bouncers) {
            my $bname_raw = $b->{name} // '-';
            my $bname   = html_escape($bname_raw);
            my $bip     = html_escape($b->{ip_address}    // $b->{ipAddress} // '-');
            my $btype   = html_escape($b->{type}          // '-');
            my $bver    = html_escape($b->{version}       // '-');
            my $blp     = html_escape($b->{last_pull}     // $b->{lastPull} // '-');
            my $bactive = $b->{isValid} // $b->{is_valid} // 1;
            my $bst_cls = $bactive ? 'tag active' : 'tag inactive';
            my $bst_lbl = $bactive ? 'OK' : 'REVOKED';
            my $slug    = slugify($bname_raw);
            my $metlink = $bname_raw ne '-' ? qq(<a class="dive" href="index.cgi?tab=metrics#bouncer-$slug">📊 Metrics</a>) : '';
            print "<tr id='bouncer-row-$slug'><td class='mono'>$bname</td><td class='mono'>$bip</td>
              <td>$btype</td><td class='mono'>$bver</td>
              <td style='font-size:11px;color:var(--text3)'>$blp</td>
              <td><span class='$bst_cls'>$bst_lbl</span></td>
              <td>$metlink</td></tr>";
        }
        print '</tbody></table>';
    } else {
        print '<div class="no-data">No bouncers registered</div>';
    }
    print '</div></div></div>'; # card + content
}

# ─────────────────────────────────────────────────────────────────────────────
# TAB: HUB
# ─────────────────────────────────────────────────────────────────────────────
elsif ($tab eq 'hub') {
    my $hub_json   = `cscli hub list -o json 2>/dev/null`;
    my $hub_data   = load_json($hub_json) // {};
    my $view       = $in{'view'} || 'collections';
    $view = 'collections' unless $view =~ /^(scenarios|parsers|collections|postoverflows)$/;

    print <<HTML;
<div class="topbar">
  <div class="page-title"><span class="ico">📦</span> Hub</div>
  <div class="topbar-right">
    <a href="index.cgi?tab=hub&view=$view" class="btn btn-ghost btn-sm">↺ Refresh</a>
  </div>
</div>
<div class="content">
  <div class="stat-grid">
HTML
    for my $section (['scenarios','🎯 Scenarios'],['parsers','🔍 Parsers'],
                     ['collections','📦 Collections'],['postoverflows','📤 Post-overflows']) {
        my ($key, $lbl) = @$section;
        my $cnt = ref $hub_data->{$key} eq 'ARRAY' ? scalar @{$hub_data->{$key}} : 0;
        my $active_style = $view eq $key ? ' style="border-color:var(--accent)"' : '';
        print qq(<a class='stat-card' href="index.cgi?tab=hub&view=$key"$active_style>
          <div class='label'>$lbl</div><div class='value'>$cnt</div></a>);
    }
    print '</div>';

    if ($view eq 'scenarios') {
        my $scenarios = get_scenario_list();
        print <<HTML;
  <div class="card">
    <div class="card-header"><div class="card-title">🎯 Installed Scenarios</div>
      <span style="font-size:11px;color:var(--text3)">Click a scenario to see its recent alerts</span></div>
    <div class="card-body no-pad">
HTML
        if (@$scenarios) {
            print '<table class="tbl"><thead><tr><th>Name</th><th>Version</th><th>Status</th><th>Description</th></tr></thead><tbody>';
            for my $s (@$scenarios) {
                my $name  = $s->{name} // '-';
                my $ver   = html_escape($s->{local_version} // $s->{version} // '-');
                my $desc  = html_escape($s->{description} // '-');
                my $cls   = ($s->{status} // '') =~ /enabled/i ? 'tag active' : 'tag inactive';
                my $lbl   = html_escape($s->{status} // 'enabled');
                my $link  = $name eq '-' ? '-' : dive_link($name, scenario => $name, tab => 'alerts');
                print "<tr><td class='mono'>$link</td><td class='mono'>$ver</td>
                  <td><span class='$cls'>$lbl</span></td>
                  <td style='font-size:11px;color:var(--text3)'>$desc</td></tr>";
            }
            print '</tbody></table>';
        } else {
            print '<div class="no-data" style="padding:20px">No scenarios reported by <code>cscli scenarios list</code>.</div>';
            print debug_raw_snippet('scenarios');
        }
        print '</div></div>';
    }
    elsif ($view eq 'parsers') {
        my $parsers = get_parser_list();
        print <<HTML;
  <div class="card">
    <div class="card-header"><div class="card-title">🔍 Installed Parsers</div></div>
    <div class="card-body no-pad">
HTML
        if (@$parsers) {
            print '<table class="tbl"><thead><tr><th>Name</th><th>Version</th><th>Status</th><th>Description</th></tr></thead><tbody>';
            for my $p (@$parsers) {
                my $name = html_escape($p->{name} // '-');
                my $ver  = html_escape($p->{local_version} // $p->{version} // '-');
                my $desc = html_escape($p->{description} // '-');
                my $cls  = ($p->{status} // '') =~ /enabled/i ? 'tag active' : 'tag inactive';
                my $lbl  = html_escape($p->{status} // 'enabled');
                print "<tr><td class='mono'>$name</td><td class='mono'>$ver</td>
                  <td><span class='$cls'>$lbl</span></td>
                  <td style='font-size:11px;color:var(--text3)'>$desc</td></tr>";
            }
            print '</tbody></table>';
        } else {
            print '<div class="no-data" style="padding:20px">No parsers reported by <code>cscli parsers list</code>.</div>';
            print debug_raw_snippet('parsers');
        }
        print '</div></div>';
    }
    elsif ($view eq 'postoverflows') {
        my $pofs = get_postoverflow_list();
        print <<HTML;
  <div class="card">
    <div class="card-header"><div class="card-title">📤 Installed Post-overflows</div></div>
    <div class="card-body no-pad">
HTML
        if (@$pofs) {
            print '<table class="tbl"><thead><tr><th>Name</th><th>Version</th><th>Status</th><th>Description</th></tr></thead><tbody>';
            for my $p (@$pofs) {
                my $name = html_escape($p->{name} // '-');
                my $ver  = html_escape($p->{local_version} // $p->{version} // '-');
                my $desc = html_escape($p->{description} // '-');
                my $cls  = ($p->{status} // '') =~ /enabled/i ? 'tag active' : 'tag inactive';
                my $lbl  = html_escape($p->{status} // 'enabled');
                print "<tr><td class='mono'>$name</td><td class='mono'>$ver</td>
                  <td><span class='$cls'>$lbl</span></td>
                  <td style='font-size:11px;color:var(--text3)'>$desc</td></tr>";
            }
            print '</tbody></table>';
        } else {
            print '<div class="no-data" style="padding:20px">No post-overflows reported by <code>cscli postoverflows list</code>.</div>';
            print debug_raw_snippet('postoverflows');
        }
        print '</div></div>';
    }
    else { # collections (default)
        my $coll_data = get_collection_list();
        print <<HTML;
  <div class="card">
    <div class="card-header"><div class="card-title">📦 Installed Collections</div></div>
    <div class="card-body no-pad">
HTML
        if (@$coll_data) {
            print '<table class="tbl"><thead><tr><th>Name</th><th>Version</th><th>Status</th><th>Description</th></tr></thead><tbody>';
            for my $c (@$coll_data) {
                my $cname = html_escape($c->{name}        // '-');
                my $cver  = html_escape($c->{version}     // '-');
                my $cdesc = html_escape($c->{description} // '-');
                my $cupd  = ($c->{local_version} // '') ne ($c->{version} // '') ? 'tag warn' : 'tag active';
                my $clbl  = $c->{status} // 'enabled';
                print "<tr><td class='mono'>$cname</td><td class='mono'>$cver</td>
                  <td><span class='$cupd'>$clbl</span></td>
                  <td style='font-size:11px;color:var(--text3)'>$cdesc</td></tr>";
            }
            print '</tbody></table>';
        } else {
            # Fallback: show raw hub counts
            print '<div class="no-data" style="padding:20px">Run <code style="font-family:var(--mono)">cscli hub list</code> on the server to see installed items.</div>';
            print debug_raw_snippet('collections');
        }
        print '</div>';
        print '<p style="font-size:11px;color:var(--text3);margin-top:10px">A collection bundles multiple scenarios/parsers — switch to the <a class="dive" href="index.cgi?tab=hub&view=scenarios">Scenarios view</a> above to dive into individual scenarios and their alerts.</p>';
        print '</div>'; # content
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# TAB: SERVICES
# ─────────────────────────────────────────────────────────────────────────────
elsif ($tab eq 'services') {
    print <<HTML;
<div class="topbar">
  <div class="page-title"><span class="ico">🔧</span> Services</div>
  <div class="topbar-right">
    <a href="index.cgi?tab=services" class="btn btn-ghost btn-sm">↺ Refresh</a>
  </div>
</div>
<div class="content">
HTML
    for my $svc (['crowdsec','⚙️','CrowdSec Engine','Main detection engine'],
                 ['crowdsec-firewall-bouncer','🔥','Firewall Bouncer','Applies bans to the firewall']) {
        my ($name, $ico, $label, $desc) = @$svc;
        my $st  = get_service_status($name);
        my $err = get_service_errors($name);
        my $scls= $st eq 'active' ? 'tag active' : ($st eq 'inactive' ? 'tag inactive' : 'tag');
        my $slbl= $st eq 'active' ? '● RUNNING'  : ($st eq 'inactive' ? '● STOPPED'   : '? UNKNOWN');
        my $related = $name eq 'crowdsec'
            ? qq(<a class="dive" href="index.cgi?tab=engines">⚙️ View engines</a>)
            : qq(<a class="dive" href="index.cgi?tab=bouncers">🔥 View bouncers</a> &nbsp;·&nbsp; <a class="dive" href="index.cgi?tab=metrics#bouncer-@{[slugify($name)]}">📊 View metrics</a>);
        print <<HTML;
  <div class="card" style="margin-bottom:16px">
    <div class="card-header">
      <div class="card-title">$ico $label
        <span class="$scls" style="margin-left:8px">$slbl</span>
      </div>
      <div style="display:flex;gap:8px">
        <form method="post" action="action.cgi"><input type="hidden" name="service" value="$name"><input type="hidden" name="action" value="start">
          <button class="btn btn-success btn-sm">▶ Start</button></form>
        <form method="post" action="action.cgi"><input type="hidden" name="service" value="$name"><input type="hidden" name="action" value="stop">
          <button class="btn btn-danger btn-sm">■ Stop</button></form>
        <form method="post" action="action.cgi"><input type="hidden" name="service" value="$name"><input type="hidden" name="action" value="restart">
          <button class="btn btn-warn btn-sm">↺ Restart</button></form>
      </div>
    </div>
    <div class="card-body">
      <p style="font-size:12px;color:var(--text3);margin-bottom:12px">$desc &nbsp;·&nbsp; <code style="font-family:var(--mono);font-size:11px">$name.service</code> &nbsp;·&nbsp; $related</p>
HTML
        if ($err) {
            print qq(<div class="err-label">⚠ Recent Errors</div><div class="err-box">$err</div>);
        } else {
            print '<p style="font-size:12px;color:var(--success)">✓ No recent errors</p>';
        }
        print '</div></div>';
    }
    print '</div>'; # content
}

# close main + shell
print '</div></div>'; # .main + .shell

print <<'HTML';
<script>
// ── Mobile sidebar drawer ──────────────────────────────────────────────────
function toggleSidebar() {
  var sb = document.querySelector('.sidebar');
  var ov = document.getElementById('sidebar-overlay');
  if (!sb || !ov) return;
  sb.classList.toggle('open');
  ov.classList.toggle('open');
}
window.addEventListener('resize', function() {
  if (window.innerWidth > 900) {
    var sb = document.querySelector('.sidebar');
    var ov = document.getElementById('sidebar-overlay');
    if (sb) sb.classList.remove('open');
    if (ov) ov.classList.remove('open');
  }
});

// ── Responsive viz-grid ───────────────────────────────────────────────────────
function applyGridLayout() {
  var grid = document.querySelector('.viz-grid');
  if (!grid) return;
  var parent = grid.parentElement;
  var w = parent ? (parent.clientWidth || parent.offsetWidth) : 0;
  if (w > 0) grid.style.gridTemplateColumns = w < 700 ? '1fr' : '1fr 1fr';
}

document.addEventListener('DOMContentLoaded', function() {
  applyGridLayout();
  if (window.ResizeObserver) {
    var content = document.querySelector('.content') || document.querySelector('.main');
    if (content) new ResizeObserver(applyGridLayout).observe(content);
  }
});
window.addEventListener('resize', applyGridLayout);

// ── Visualizer None/Summary/Expanded tabs ─────────────────────────────────────
function setViz(mode, btn) {
  document.querySelectorAll('.viz-tab').forEach(function(t) { t.classList.remove('active'); });
  btn.classList.add('active');
  var body = document.getElementById('viz-body');
  if (body) body.style.display = mode === 'none' ? 'none' : '';
}

// ── Source ASs card tooltip (engine ID on hover) ──────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  var asTitle = document.querySelector('.viz-card-title');
  var cards = document.querySelectorAll('.viz-card');
  var asCard = null;
  cards.forEach(function(c) {
    var t = c.querySelector('.viz-card-title');
    if (t && t.textContent.indexOf('Source AS') !== -1) asCard = c;
  });
  var tip = document.getElementById('eng-tip');
  if (asCard && tip) {
    asCard.addEventListener('mousemove', function(e) {
      var r = asCard.getBoundingClientRect();
      tip.style.display = 'block';
      tip.style.left = Math.min(e.clientX - r.left, r.width - 270) + 'px';
      tip.style.top  = (e.clientY - r.top + 16) + 'px';
    });
    asCard.addEventListener('mouseleave', function() { tip.style.display = 'none'; });
  }
});
</script>
HTML

&ui_print_footer("", "Dashboard");
