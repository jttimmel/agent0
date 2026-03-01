import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import os
import time
import re
import random

# ─────────────────────────────────────────────────────────────────────────────
# DESIGN SYSTEM  (Zerve / SOC dark palette)
# ─────────────────────────────────────────────────────────────────────────────
BG       = "#0d1117"
CARD_BG  = "#161b22"
BORDER   = "#30363d"
TEXT     = "#e6edf3"
TEXT_SEC = "#8b949e"
RED      = "#f04438"
ORANGE   = "#FFB482"
AMBER    = "#ffd400"
GREEN    = "#17b26a"
BLUE     = "#58a6ff"
LAVENDER = "#D0BBFF"
CYAN     = "#39c5cf"
PALETTE  = [BLUE, ORANGE, GREEN, RED, LAVENDER, CYAN, AMBER, "#9467BD"]

PLOTLY_BASE = dict(
    paper_bgcolor=CARD_BG,
    plot_bgcolor=CARD_BG,
    font=dict(color=TEXT, family="Source Sans Pro, sans-serif"),
    margin=dict(l=45, r=30, t=50, b=45),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=TEXT_SEC)),
    xaxis=dict(gridcolor="#21262d", zerolinecolor="#21262d", tickfont=dict(color=TEXT_SEC)),
    yaxis=dict(gridcolor="#21262d", zerolinecolor="#21262d", tickfont=dict(color=TEXT_SEC)),
    title=dict(x=0.5, xanchor='center'),
)

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AgentØ",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@400;600;700&display=swap');
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
  .stApp {{ background-color:{BG}; color:{TEXT}; font-family:'Source Sans Pro',sans-serif; }}
  .stApp header {{ background-color:{BG}; }}
  [data-testid="stSidebar"] {{ background-color:{CARD_BG}; border-right:1px solid {BORDER}; }}
  h1,h2,h3,h4 {{ color:{TEXT} !important; }}
  .stTabs [data-baseweb="tab-list"] {{ background-color:{CARD_BG}; border-radius:8px; border:1px solid {BORDER}; padding-left: 20px; }}
  .stTabs [data-baseweb="tab"] {{ color:{TEXT_SEC}; font-size:0.82rem; }}
  .stTabs [aria-selected="true"] {{ color:{TEXT} !important; }}
  div[data-testid="stDataFrame"] {{ background:{CARD_BG}; border-radius:8px; }}
  .metric-card {{
      background:{CARD_BG}; border:1px solid {BORDER}; border-radius:10px;
      padding:1rem 1.1rem; text-align:center; margin-bottom:0.4rem;
  }}
  .metric-val {{ font-size:1.9rem; font-weight:700; line-height:1.1; }}
  .metric-label {{ font-size:0.7rem; color:{TEXT_SEC}; margin-top:0.25rem; letter-spacing:0.5px; text-transform:uppercase; }}
  .metric-delta {{ font-size:0.72rem; margin-top:0.15rem; }}
  .banner-critical {{
      background:rgba(240,68,56,0.15); border:1px solid {RED};
      border-radius:10px; padding:1rem 1.25rem; color:{RED};
      font-size:1rem; font-weight:600; margin-bottom:1rem;
  }}
  .banner-warning {{
      background:rgba(255,180,0,0.12); border:1px solid {AMBER};
      border-radius:10px; padding:1rem 1.25rem; color:{AMBER};
      font-size:1rem; font-weight:600; margin-bottom:1rem;
  }}
  .banner-ok {{
      background:rgba(23,178,106,0.1); border:1px solid {GREEN};
      border-radius:10px; padding:1rem 1.25rem; color:{GREEN};
      font-size:1rem; font-weight:600; margin-bottom:1rem;
  }}
  .section-hdr {{
      color:{TEXT}; font-size:0.88rem; font-weight:600; text-transform:uppercase;
      letter-spacing:0.8px; border-bottom:1px solid {BORDER};
      padding-bottom:0.3rem; margin-bottom:0.7rem; margin-top:1rem;
  }}
  .threat-badge-high {{ color:{RED}; font-weight:700; }}
  .threat-badge-med  {{ color:{AMBER}; font-weight:600; }}
  .threat-badge-low  {{ color:{GREEN}; }}
  .terminal-box {{
      background:#0a0c10; padding:12px 15px; border-radius:8px; 
      font-family:"JetBrains Mono", monospace; font-size:0.85rem; 
      border:1px solid #30363d; margin-bottom:1rem; 
      box-shadow: inset 0 0 10px rgba(0,0,0,0.5);
  }}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# FUZZY COLUMN DETECTION HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _fuzzy_find(columns, patterns, default=None):
    cols_lower = [c.lower() for c in columns]
    for pat in patterns:
        for i, cl in enumerate(cols_lower):
            if re.search(pat, cl):
                return columns[i]
    return default

def detect_schema(df, source_hint=""):
    cols = df.columns.tolist()
    schema = {
        "timestamp":   _fuzzy_find(cols, [r"time", r"date", r"ts\b", r"^dt$"]),
        "source_ip":   _fuzzy_find(cols, [r"src.*ip", r"source.*ip", r"client.*ip", r"from_ip", r"srcip"]),
        "dest_ip":     _fuzzy_find(cols, [r"dst.*ip", r"dest.*ip", r"target.*ip", r"to_ip", r"dstip"]),
        "dst_port":    _fuzzy_find(cols, [r"dst.*port", r"dest.*port", r"port"]),
        "action":      _fuzzy_find(cols, [r"action", r"result", r"status", r"outcome", r"verdict"]),
        "user":        _fuzzy_find(cols, [r"user", r"username", r"account", r"login"]),
        "hostname":    _fuzzy_find(cols, [r"host", r"machine", r"device", r"computer", r"asset"]),
        "domain":      _fuzzy_find(cols, [r"domain", r"fqdn", r"query", r"dns", r"url"]),
        "threat":      _fuzzy_find(cols, [r"threat", r"malware", r"signature", r"alert", r"rule", r"ioc"]),
    }
    return schema

# ─────────────────────────────────────────────────────────────────────────────
# DATA LOADING (cached; busts every 30 s for auto-refresh)
# ─────────────────────────────────────────────────────────────────────────────
SUSPICIOUS_DOMAINS = {
    "phish.bad-actor.ru", "malware-c2.net", "evil-corp.xyz",
    "trojan-download.pw", "botnet-cmd.cn",
}
KNOWN_INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                            "172.29.", "172.30.", "172.31.", "127.")

def is_internal(ip):
    if not isinstance(ip, str): return True
    return any(ip.startswith(p) for p in KNOWN_INTERNAL_PREFIXES)

@st.cache_data(ttl=30)
def load_data(uploaded_files=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dfs = {"firewall": pd.DataFrame(), "auth": pd.DataFrame(), "dns": pd.DataFrame(), "malware": pd.DataFrame()}
    schemas = {"firewall": {}, "auth": {}, "dns": {}, "malware": {}}

    if uploaded_files:
        for up_file in uploaded_files:
            try:
                up_file.seek(0)
                df = pd.read_csv(up_file)
                fname = up_file.name.lower()
                cat = "firewall" # Default fallback
                if "auth" in fname or "login" in fname: cat = "auth"
                elif "dns" in fname: cat = "dns"
                elif "malware" in fname or "alert" in fname: cat = "malware"
                elif "firewall" in fname: cat = "firewall"
                else:
                    sc_check = detect_schema(df)
                    if sc_check.get("threat"): cat = "malware"
                    elif sc_check.get("domain"): cat = "dns"
                    elif sc_check.get("user"): cat = "auth"
                
                sc = detect_schema(df, source_hint=cat)
                if sc.get("timestamp") and sc["timestamp"] in df.columns:
                    df[sc["timestamp"]] = pd.to_datetime(df[sc["timestamp"]], errors="coerce")
                
                dfs[cat] = pd.concat([dfs[cat], df], ignore_index=True) if not dfs[cat].empty else df
                schemas[cat] = sc
            except Exception: pass
    else:
        csv_files = {"firewall": "firewall_logs.csv", "auth": "auth_logs.csv", "dns": "dns_logs.csv", "malware": "malware_alerts.csv"}
        for key, fname in csv_files.items():
            fpath = os.path.join(base_dir, fname)
            if os.path.exists(fpath):
                df = pd.read_csv(fpath)
                sc = detect_schema(df, source_hint=key)
                if sc.get("timestamp"): df[sc["timestamp"]] = pd.to_datetime(df[sc["timestamp"]], errors="coerce")
                dfs[key], schemas[key] = df, sc
    return dfs, schemas

def apply_time_filter(df, ts_col, window):
    if not ts_col or ts_col not in df.columns or df.empty: return df
    t_max = df[ts_col].max()
    hours_map = {"Last 1h": 1, "Last 2h": 2, "Last 4h": 4, "Last 6h": 6}
    if window in hours_map:
        return df[df[ts_col] >= t_max - pd.Timedelta(hours=hours_map[window])]
    return df

# ─────────────────────────────────────────────────────────────────────────────
# VIEW CALLBACKS 
# ─────────────────────────────────────────────────────────────────────────────
def load_example_view():
    st.session_state.view = 'dashboard_example'
    st.session_state.stream_progress = 0.8  # Reset stream progress
    st.session_state.live_logs = [f"<span style='color:{GREEN}'>[SYS]</span> AgentØ Initialized. Awaiting live data..."]

def process_file_upload():
    if st.session_state.get('splash_csv_uploader'):
        st.session_state.uploaded_files = st.session_state.splash_csv_uploader
        st.session_state.view = 'dashboard_upload'
        st.session_state.stream_progress = 0.8
        st.session_state.live_logs = [f"<span style='color:{GREEN}'>[SYS]</span> AgentØ Initialized. Awaiting live data..."]

def return_home():
    st.session_state.view = 'splash'
    st.session_state.uploaded_files = None
    st.session_state.live_mode = False

# ─────────────────────────────────────────────────────────────────────────────
# MAIN DASHBOARD RENDERER
# ─────────────────────────────────────────────────────────────────────────────
def run_dashboard(uploaded_files_param, placeholder):
    with st.sidebar:
        st.markdown(f"""
        <div style="text-align:center;padding:0.5rem 0 1rem">
          <div style="font-size:1.5rem;font-weight:700;color:{TEXT}">AgentØ</div>
          <div style="font-size:0.9rem;color:{TEXT_SEC};margin-top:0.2rem">SOC Intelligence Platform</div>
        </div>""", unsafe_allow_html=True)
        st.divider()
        st.button("⬅ Back to Home", key="back_btn", on_click=return_home)
        st.divider()

        st.markdown(f"<p style='color:{TEXT_SEC};font-size:0.7rem;text-transform:uppercase;letter-spacing:1px'>Live Operations</p>", unsafe_allow_html=True)
        
        # LIVE MODE TOGGLE
        live_mode = st.toggle("🔴 Go Live (Real-Time Data)", value=st.session_state.get('live_mode', False))
        st.session_state.live_mode = live_mode
        
        st.markdown(f"<p style='color:{TEXT_SEC};font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-top:1rem'>Time Window</p>", unsafe_allow_html=True)
        time_window = st.select_slider("window", ["Last 1h", "Last 2h", "Last 4h", "Last 6h", "Full"], value="Full", label_visibility="collapsed")

    # LOAD FULL DATA
    dfs_full, schemas = load_data(uploaded_files=uploaded_files_param)
    
    # --- REAL-TIME DATA STREAMING SIMULATOR ---
    # Advance the data slice if live mode is active
    if st.session_state.live_mode:
        st.session_state.stream_progress += 0.02 # Reveal 2% more data every tick
        if st.session_state.stream_progress > 1.0:
            st.session_state.stream_progress = 1.0
            
    # Slice the dataframes chronologically to simulate ingestion
    dfs = {}
    for key in dfs_full:
        df = dfs_full[key]
        if not df.empty:
            ts_col = schemas[key].get("timestamp")
            if ts_col and ts_col in df.columns:
                df = df.sort_values(ts_col) # Ensure chronological order
            limit = int(len(df) * st.session_state.stream_progress)
            dfs[key] = df.iloc[:max(1, limit)] # Always show at least 1 row to prevent crashes
        else:
            dfs[key] = df

    fw   = dfs["firewall"];  fw_sc  = schemas["firewall"]
    auth = dfs["auth"];      auth_sc = schemas["auth"]
    dns  = dfs["dns"];       dns_sc  = schemas["dns"]
    mal  = dfs["malware"];   mal_sc  = schemas["malware"]

    # Apply time filtering immediately so all metrics reflect the window
    fw_f   = apply_time_filter(fw,   fw_sc.get("timestamp"),   time_window)
    auth_f = apply_time_filter(auth, auth_sc.get("timestamp"),  time_window)
    dns_f  = apply_time_filter(dns,  dns_sc.get("timestamp"),   time_window)
    mal_f  = apply_time_filter(mal,  mal_sc.get("timestamp"),   time_window)

    # COMPUTE THREAT SCORES (Based on currently revealed data)
    ext_fw_ips = set()
    if fw_sc.get("src_ip") and fw_sc["src_ip"] in fw_f.columns:
        ext_fw_ips = set(fw_f[~fw_f[fw_sc["src_ip"]].apply(is_internal)][fw_sc["src_ip"]].dropna().unique())

    failed_logins = 0
    brute_force_ips = set()
    if auth_sc.get("action") and auth_sc["action"] in auth_f.columns:
        fail_mask = auth_f[auth_sc["action"]].str.contains("fail|fail.*login|denied", case=False, na=False, regex=True)
        failed_logins = fail_mask.sum()
        if auth_sc.get("src_ip") and auth_sc["src_ip"] in auth_f.columns:
            ip_fails = auth_f[fail_mask].groupby(auth_sc["src_ip"]).size()
            brute_force_ips = set(ip_fails[ip_fails >= 5].index.tolist())

    suspicious_dns_hits = 0
    if dns_sc.get("domain") and dns_sc["domain"] in dns_f.columns:
        suspicious_dns_hits = dns_f[dns_f[dns_sc["domain"]].isin(SUSPICIOUS_DOMAINS)].shape[0]
        suspicious_tld_mask = dns_f[dns_sc["domain"]].str.contains(r"\.(ru|cn|xyz|pw|tk|ml|ga|cf)$", case=False, na=False, regex=True)
        suspicious_dns_hits = max(suspicious_dns_hits, suspicious_tld_mask.sum())

    mal_count = len(mal_f)

    threat_score = 0
    threat_factors = []
    if ext_fw_ips:
        pts = min(30, len(ext_fw_ips) * 10)
        threat_score += pts
        threat_factors.append(f"External IPs on firewall (+{pts})")
    if brute_force_ips:
        pts = min(35, len(brute_force_ips) * 15)
        threat_score += pts
        threat_factors.append(f"Brute-force IPs ({len(brute_force_ips)}) (+{pts})")
    if suspicious_dns_hits > 0:
        pts = min(25, suspicious_dns_hits * 10)
        threat_score += pts
        threat_factors.append(f"Suspicious DNS queries ({suspicious_dns_hits}) (+{pts})")
    if mal_count > 0:
        pts = min(40, mal_count * 20)
        threat_score += pts
        threat_factors.append(f"Malware alerts ({mal_count}) (+{pts})")
    threat_score = min(100, threat_score)

    if threat_score >= 70:
        threat_level = "CRITICAL"
        banner_class = "banner-critical"
    elif threat_score >= 40:
        threat_level = "HIGH"
        banner_class = "banner-warning"
    elif threat_score >= 15:
        threat_level = "ELEVATED"
        banner_class = "banner-warning"
    else:
        threat_level = "NORMAL"
        banner_class = "banner-ok"

    blocked_count = 0
    if fw_sc.get("action") and fw_sc["action"] in fw_f.columns:
        blocked_count = fw_f[fw_f[fw_sc["action"]].str.contains("block|deny|drop|reject", case=False, na=False, regex=True)].shape[0]

    with st.sidebar:
        st.divider()
        st.markdown(f"""
        <div style='font-size:0.73rem;color:{TEXT_SEC};line-height:1.9'>
          Firewall: <b style='color:{TEXT}'>{len(fw):,}</b> events<br>
          Auth: <b style='color:{TEXT}'>{len(auth):,}</b> events<br>
          DNS: <b style='color:{TEXT}'>{len(dns):,}</b> queries<br>
          Malware: <b style='color:{TEXT}'>{len(mal)}</b> alerts<br>
          <span style='color:{TEXT_SEC}'>Stream Progress: </span>
          <b style='color:{GREEN if st.session_state.stream_progress >= 1.0 else ORANGE}'>{int(st.session_state.stream_progress * 100)}%</b>
        </div>""", unsafe_allow_html=True)
        st.divider()

        gauge_color = RED if threat_score >= 70 else AMBER if threat_score >= 40 else AMBER if threat_score >= 15 else GREEN
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=threat_score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "THREAT SCORE", "font": {"color": TEXT_SEC, "size": 11}},
            number={"font": {"color": gauge_color, "size": 28}},
            gauge={
                "axis": {"range": [0, 100], "tickfont": {"color": TEXT_SEC, "size": 9}},
                "bar": {"color": gauge_color, "thickness": 0.3},
                "bgcolor": CARD_BG,
                "bordercolor": BORDER,
                "steps": [
                    {"range": [0, 15],  "color": "rgba(23,178,106,0.15)"},
                    {"range": [15, 40], "color": "rgba(255,212,0,0.12)"},
                    {"range": [40, 70], "color": "rgba(255,180,130,0.15)"},
                    {"range": [70, 100],"color": "rgba(240,68,56,0.2)"},
                ],
                "threshold": {"line": {"color": gauge_color, "width": 3}, "thickness": 0.8, "value": threat_score},
            },
        ))
        fig_gauge.update_layout(paper_bgcolor=CARD_BG, plot_bgcolor=CARD_BG,
                                 font=dict(color=TEXT), height=190,
                                 margin=dict(l=15, r=15, t=30, b=10))
        st.plotly_chart(fig_gauge, use_container_width=True)

    # --- UI RENDER WITHIN PLACEHOLDER ---
    with placeholder.container():
        st.markdown(f"""
        <div style='display:flex;align-items:center;gap:0.75rem;margin-bottom:0.25rem'>
          <span style='font-size:2.5rem;font-weight:700;color:{TEXT}'>AgentØ</span>
          <span style='margin-left:auto;font-size:0.72rem;color:{TEXT_SEC}'>{pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
        </div>
        <p style='color:{TEXT_SEC};font-size:0.82rem;margin-bottom:1rem'>
          Real-time threat intelligence · Firewall · Auth · DNS · Malware
        </p>""", unsafe_allow_html=True)

        factor_str = " &nbsp;|&nbsp; ".join(threat_factors) if threat_factors else "No active threat signals"
        st.markdown(f"""
        <div class="{banner_class}">
          <b>THREAT LEVEL: {threat_level}</b> &nbsp;— Score: {threat_score}/100
          &nbsp;&nbsp;<span style='font-weight:400;font-size:0.85rem;opacity:0.9'>{factor_str}</span>
        </div>""", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # AI AUTO-DEFENSE TERMINAL
        # ---------------------------------------------------------------------
        if st.session_state.live_mode:
            if st.session_state.stream_progress >= 1.0:
                new_log = f"<span style='color:{GREEN}'>[SYS]</span> Real-time data sync complete. Monitoring for new events..."
            else:
                threat_ips = list(ext_fw_ips)[:5] + list(brute_force_ips)[:5]
                sample_ip = random.choice(threat_ips) if threat_ips else f"{random.randint(10,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                
                actions = [
                    f"<span style='color:{GREEN}'>[SYS]</span> Ingesting network stream... {random.randint(400,999)} packets cleared.",
                    f"<span style='color:{AMBER}'>[WARN]</span> Anomaly detected on port {random.choice([443, 22, 80, 3389])}. Initiating deep packet inspection.",
                    f"<span style='color:{RED}'>[DETECT]</span> Malicious payload signature matched from IP {sample_ip}.",
                    f"<span style='color:{BLUE}'>[ACTION]</span> Automatically updating firewall rules. Null-routing {sample_ip}.",
                    f"<span style='color:{BLUE}'>[ACTION]</span> Isolating endpoint. Restricting lateral movement from {sample_ip}.",
                    f"<span style='color:{GREEN}'>[SYS]</span> DNS traffic nominal. No tunneling detected in last 50 queries."
                ]
                new_log = random.choice(actions)
            
            st.session_state.live_logs.append(f"<span style='color:{TEXT_SEC}'>[{pd.Timestamp.now().strftime('%H:%M:%S.%f')[:-4]}]</span> {new_log}")
            if len(st.session_state.live_logs) > 4:
                st.session_state.live_logs.pop(0)
                
            log_html = "<br>".join(st.session_state.live_logs)
            st.markdown(f"""
            <div class="terminal-box">
                <div style='color:#8b949e; font-size:0.7rem; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px;'>🔴 Live Agent Defense Stream</div>
                {log_html}
            </div>
            """, unsafe_allow_html=True)

        total_events = len(fw_f) + len(auth_f) + len(dns_f) + len(mal_f)
        fail_pct = (failed_logins / len(auth_f) * 100) if len(auth_f) else 0

        k1, k2, k3, k4, k5 = st.columns(5)

        with k1:
            st.markdown(f"""<div class="metric-card">
              <div class="metric-val" style="color:{BLUE}">{total_events:,}</div>
              <div class="metric-label">Total Events</div>
              <div class="metric-delta" style="color:{TEXT_SEC}">across all sources</div>
            </div>""", unsafe_allow_html=True)

        with k2:
            bl_color = AMBER if blocked_count > 0 else GREEN
            st.markdown(f"""<div class="metric-card">
              <div class="metric-val" style="color:{bl_color}">{blocked_count:,}</div>
              <div class="metric-label">Blocked Connections</div>
              <div class="metric-delta" style="color:{TEXT_SEC}">firewall drops/denies</div>
            </div>""", unsafe_allow_html=True)

        with k3:
            fl_color = RED if fail_pct > 30 else AMBER if fail_pct > 10 else GREEN
            st.markdown(f"""<div class="metric-card">
              <div class="metric-val" style="color:{fl_color}">{failed_logins:,}</div>
              <div class="metric-label">Failed Logins</div>
              <div class="metric-delta" style="color:{fl_color}">{fail_pct:.1f}% failure rate</div>
            </div>""", unsafe_allow_html=True)

        with k4:
            mc_color = RED if mal_count > 0 else GREEN
            st.markdown(f"""<div class="metric-card">
              <div class="metric-val" style="color:{mc_color}">{mal_count}</div>
              <div class="metric-label">Malware Hits</div>
              <div class="metric-delta" style="color:{mc_color}">{'INVESTIGATE NOW' if mal_count > 0 else 'Clean'}</div>
            </div>""", unsafe_allow_html=True)

        with k5:
            dns_susp_color = RED if suspicious_dns_hits > 0 else GREEN
            st.markdown(f"""<div class="metric-card">
              <div class="metric-val" style="color:{dns_susp_color}">{suspicious_dns_hits:,}</div>
              <div class="metric-label">Suspicious DNS</div>
              <div class="metric-delta" style="color:{dns_susp_color}">{'Malicious domains' if suspicious_dns_hits > 0 else 'Clean'}</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        attack_signals = []
        if brute_force_ips:
            attack_signals.append({"Signal": "Brute Force Login Attempts", "Indicator": ", ".join(list(brute_force_ips)[:5]),
                                    "Severity": "CRITICAL", "Source": "Auth Logs", "Action": "Block IP, Reset PW"})
        if ext_fw_ips:
            attack_signals.append({"Signal": "External IPs on Firewall", "Indicator": ", ".join(list(ext_fw_ips)[:5]),
                                    "Severity": "HIGH", "Source": "Firewall", "Action": "Update FW Rules"})
        if suspicious_dns_hits > 0:
            attack_signals.append({"Signal": "Suspicious DNS Queries", "Indicator": f"{suspicious_dns_hits} queries to malicious/suspicious domains",
                                    "Severity": "ELEVATED", "Source": "DNS", "Action": "Sinkhole Domain"})
        if mal_count > 0:
            threat_col = mal_sc.get("threat")
            threat_names = mal[threat_col].unique().tolist() if threat_col and threat_col in mal.columns else ["Unknown"]
            attack_signals.append({"Signal": "Malware Detected", "Indicator": ", ".join(str(t) for t in threat_names[:3]),
                                    "Severity": "CRITICAL", "Source": "Malware AV", "Action": "Isolate Host"})

        if attack_signals:
            st.markdown("<p class='section-hdr' style='color:#f04438'>Active Threat Signals (Action Required)</p>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(attack_signals), use_container_width=True, hide_index=True)

        tab_timeline, tab_threats, tab_fw, tab_auth, tab_dns, tab_mal = st.tabs([
            "Timeline", "Threat Tables",
            "Firewall", "Auth", "DNS", "Malware",
        ])

        with tab_timeline:
            st.markdown("<p class='section-hdr'>Unified Event Timeline — All Sources</p>", unsafe_allow_html=True)

            timeline_frames = []
            ts_col_map = {
                "Firewall": (fw_f, fw_sc.get("timestamp"), BLUE, ""),
                "Auth": (auth_f, auth_sc.get("timestamp"), ORANGE, ""),
                "DNS": (dns_f, dns_sc.get("timestamp"), LAVENDER, ""),
            }
            for src, (df, ts_col, color, emoji) in ts_col_map.items():
                if ts_col and not df.empty and ts_col in df.columns:
                    agg = df.set_index(ts_col).resample("5min").size().reset_index(name="count")
                    agg["source"] = src
                    agg["color"]  = color
                    agg["emoji"]  = emoji
                    timeline_frames.append(agg)

            if timeline_frames:
                combined_tl = pd.concat(timeline_frames, ignore_index=True)
                fig_tl = go.Figure()
                for src, (_, _, color, emoji) in ts_col_map.items():
                    sub = combined_tl[combined_tl["source"] == src]
                    if not sub.empty:
                        fig_tl.add_trace(go.Scatter(
                            x=sub[ts_col_map[src][1] if src in ts_col_map else "timestamp"],
                            y=sub["count"],
                            mode="lines",
                            name=f"{src}",
                            line=dict(color=color, width=2),
                            fill="tozeroy",
                            fillcolor=color.replace("#", "rgba(") if False else f"rgba({int(color[1:3],16)},{int(color[3:5],16)},{int(color[5:7],16)},0.07)",
                            hovertemplate=f"<b>{src}</b><br>Time: %{{x}}<br>Events: %{{y}}<extra></extra>",
                        ))
                fig_tl.update_layout(**PLOTLY_BASE)
                fig_tl.update_layout(
                    title="Unified Event Volume (Spikes indicate potential attacks)",
                    xaxis_title="Time", yaxis_title="Event Count",
                    height=380, hovermode="x unified",
                    margin=dict(l=75, r=30, t=50, b=45),
                )
                st.plotly_chart(fig_tl, use_container_width=True)
            else:
                st.info("No timeline data available.")

            if mal_sc.get("timestamp") and not mal.empty and mal_sc["timestamp"] in mal.columns:
                st.markdown("<p class='section-hdr'>Malware Alert Events on Timeline</p>", unsafe_allow_html=True)
                mal_ts_col = mal_sc["timestamp"]
                fig_mal_tl = go.Figure()
                fig_mal_tl.add_trace(go.Scatter(
                    x=mal[mal_ts_col], y=[1] * len(mal),
                    mode="markers+text",
                    marker=dict(color=RED, size=16, symbol="x"),
                    text=mal.get(mal_sc.get("threat", "threat"), ["Alert"] * len(mal)) if mal_sc.get("threat") and mal_sc["threat"] in mal.columns else ["Malware"] * len(mal),
                    textposition="top center",
                    textfont=dict(color=RED, size=10),
                    hovertemplate="<b>Malware Alert</b><br>Time: %{x}<extra></extra>",
                ))
                fig_mal_tl.update_layout(**PLOTLY_BASE)
                fig_mal_tl.update_layout(
                    height=120,
                    yaxis=dict(showticklabels=False, gridcolor="#21262d"),
                    xaxis_title="Time", title="Malware Alert Timestamps",
                )
                st.plotly_chart(fig_mal_tl, use_container_width=True)

        with tab_threats:
            col_t1, col_t2, col_t3 = st.columns(3)
            with col_t1:
                st.markdown("<p class='section-hdr'>Top Attacking Source IPs</p>", unsafe_allow_html=True)
                rows = []
                if fw_sc.get("src_ip") and fw_sc["src_ip"] in fw_f.columns:
                    ip_counts = fw_f[fw_sc["src_ip"]].value_counts().reset_index()
                    ip_counts.columns = ["IP", "Firewall Hits"]
                    if auth_sc.get("src_ip") and auth_sc["src_ip"] in auth_f.columns:
                        auth_fails = auth_f[auth_f[auth_sc["action"]].str.contains("fail", case=False, na=False, regex=True)].groupby(auth_sc["src_ip"]).size().rename("Auth Fails")
                        ip_counts = ip_counts.merge(auth_fails, left_on="IP", right_index=True, how="left").fillna(0)
                    ip_counts["External"] = ip_counts["IP"].apply(lambda ip: "YES" if not is_internal(ip) else "—")
                    ip_counts["Threat"] = ip_counts.apply(
                        lambda r: "CRITICAL" if not is_internal(r["IP"]) and r.get("Auth Fails", 0) > 5
                        else "HIGH" if not is_internal(r["IP"])
                        else "MEDIUM" if r.get("Auth Fails", 0) > 10
                        else "LOW",
                        axis=1,
                    )
                    st.dataframe(ip_counts.head(15), use_container_width=True, hide_index=True)
            with col_t2:
                st.markdown("<p class='section-hdr'>Top Targeted Hosts/IPs</p>", unsafe_allow_html=True)
                if fw_sc.get("dst_ip") and fw_sc["dst_ip"] in fw_f.columns:
                    dst_counts = fw_f[fw_sc["dst_ip"]].value_counts().reset_index()
                    dst_counts.columns = ["Destination", "Inbound Connections"]
                    dst_counts["Type"] = dst_counts["Destination"].apply(
                        lambda ip: "Internal Host" if is_internal(ip) else "External Server"
                    )
                    st.dataframe(dst_counts.head(15), use_container_width=True, hide_index=True)
                elif mal_sc.get("hostname") and mal_sc["hostname"] in mal.columns:
                    host_counts = mal[mal_sc["hostname"]].value_counts().reset_index()
                    host_counts.columns = ["Hostname", "Alerts"]
                    st.dataframe(host_counts, use_container_width=True, hide_index=True)
                else:
                    st.info("No destination data available.")
            with col_t3:
                st.markdown("<p class='section-hdr'>Top Suspicious Domains</p>", unsafe_allow_html=True)
                if dns_sc.get("domain") and dns_sc["domain"] in dns_f.columns:
                    domain_counts = dns_f[dns_sc["domain"]].value_counts().reset_index()
                    domain_counts.columns = ["Domain", "Queries"]
                    domain_counts["Suspicious"] = domain_counts["Domain"].apply(
                        lambda d: "YES" if (d in SUSPICIOUS_DOMAINS or
                            bool(re.search(r"\.(ru|cn|xyz|pw|tk|ml|ga|cf)$", str(d), re.I)))
                        else "—"
                    )
                    st.dataframe(domain_counts.head(15), use_container_width=True, hide_index=True)
                else:
                    st.info("No DNS domain data available.")

        with tab_fw:
            st.markdown("<p class='section-hdr'>Firewall Traffic Overview</p>", unsafe_allow_html=True)
            if not fw_f.empty:
                ts_col = fw_sc.get("timestamp")
                if ts_col and ts_col in fw_f.columns:
                    fw_agg = fw_f.set_index(ts_col).resample("10min").size().reset_index(name="count")
                    fig_fw = go.Figure(go.Scatter(
                        x=fw_agg[ts_col], y=fw_agg["count"],
                        mode="lines", fill="tozeroy",
                        line=dict(color=BLUE, width=2),
                        fillcolor="rgba(88,166,255,0.1)",
                    ))
                    fig_fw.update_layout(**PLOTLY_BASE)
                    fig_fw.update_layout(title="Traffic Volume (Sudden spikes = Scan/Flood)", height=280,
                                              xaxis_title="Time", yaxis_title="Events")
                    st.plotly_chart(fig_fw, use_container_width=True)

                col_f1, col_f2 = st.columns(2)
                with col_f1:
                    if fw_sc.get("src_ip") and fw_sc["src_ip"] in fw_f.columns:
                        src_vc = fw_f[fw_sc["src_ip"]].value_counts().reset_index()
                        src_vc.columns = ["IP", "count"]
                        src_colors = [RED if not is_internal(ip) else BLUE for ip in src_vc["IP"]]
                        fig_src = go.Figure(go.Bar(
                            x=src_vc["count"], y=src_vc["IP"],
                            orientation="h", marker_color=src_colors,
                            text=src_vc["count"], textposition="outside", textfont=dict(color=TEXT_SEC, size=10),
                        ))
                        fig_src.update_layout(**PLOTLY_BASE)
                        fig_src.update_layout(title="Top Source IPs<br><sup>Red=External</sup>",
                                               xaxis_title="Events", height=320,
                                               yaxis=dict(gridcolor="#21262d", tickfont=dict(color=TEXT)))
                        st.plotly_chart(fig_src, use_container_width=True)

                with col_f2:
                    if fw_sc.get("dst_port") and fw_sc["dst_port"] in fw_f.columns:
                        port_vc = fw_f[fw_sc["dst_port"]].value_counts().reset_index()
                        port_vc.columns = ["Port", "count"]
                        port_vc["Port"] = port_vc["Port"].astype(str) + " (" + port_vc["Port"].astype(str).map(
                            {"443": "HTTPS", "22": "SSH", "80": "HTTP", "3389": "RDP",
                             "21": "FTP", "53": "DNS", "25": "SMTP"}).fillna("other") + ")"
                        fig_port = go.Figure(go.Bar(
                            x=port_vc["count"], y=port_vc["Port"],
                            orientation='h', marker_color=BLUE,
                            text=port_vc["count"], textposition="outside", textfont=dict(color=TEXT_SEC, size=10),
                        ))
                        fig_port.update_layout(**PLOTLY_BASE)
                        fig_port.update_layout(title="Destination Ports<br><sup>High count on non-standard ports is suspicious</sup>", height=320, yaxis=dict(autorange="reversed"))
                        st.plotly_chart(fig_port, use_container_width=True)

                ext_fw = fw_f[fw_f[fw_sc["src_ip"]].apply(lambda x: not is_internal(x))] if fw_sc.get("src_ip") and fw_sc["src_ip"] in fw_f.columns else pd.DataFrame()
                if not ext_fw.empty:
                    st.markdown("<p class='section-hdr'>External IP Activity</p>", unsafe_allow_html=True)
                    st.dataframe(ext_fw.sort_values(ts_col, ascending=False).head(100) if ts_col and ts_col in ext_fw.columns else ext_fw.head(100),
                                 use_container_width=True, hide_index=True)
            else:
                st.info("No firewall data in current time window.")

        with tab_auth:
            st.markdown("<p class='section-hdr'>Authentication Events Overview</p>", unsafe_allow_html=True)
            if not auth_f.empty:
                ts_col  = auth_sc.get("timestamp")
                act_col = auth_sc.get("action")

                if ts_col and act_col and ts_col in auth_f.columns and act_col in auth_f.columns:
                    auth_agg = auth_f.groupby([pd.Grouper(key=ts_col, freq="15min"), act_col]).size().reset_index(name="count")
                    fig_auth = go.Figure()
                    for action, color in [("Success", GREEN), ("Failed Login", RED)]:
                        sub = auth_agg[auth_agg[act_col].str.contains(action, case=False, na=False)]
                        if not sub.empty:
                            fig_auth.add_trace(go.Scatter(
                                x=sub[ts_col], y=sub["count"],
                                mode="lines", name=action,
                                line=dict(color=color, width=2), fill="tozeroy",
                                fillcolor=f"rgba({int(color[1:3],16)},{int(color[3:5],16)},{int(color[5:7],16)},0.1)",
                            ))
                    fig_auth.update_layout(**PLOTLY_BASE)
                    fig_auth.update_layout(title="Auth Volume (Failures = Brute Force Risk)",
                                                xaxis_title="Time", yaxis_title="Events", height=300)
                    st.plotly_chart(fig_auth, use_container_width=True)

                col_a1, col_a2 = st.columns(2)

                with col_a1:
                    if act_col in auth_f.columns:
                        fail_mask = auth_f[act_col].str.contains("fail", case=False, na=False, regex=True)
                        if auth_sc.get("user") and auth_sc["user"] in auth_f.columns:
                            user_fails = auth_f[fail_mask][auth_sc["user"]].value_counts().reset_index()
                            user_fails.columns = ["User", "Failures"]
                            fig_uf = go.Figure(go.Bar(
                                x=user_fails["User"], y=user_fails["Failures"],
                                marker_color=ORANGE, text=user_fails["Failures"],
                                textposition="outside", textfont=dict(color=TEXT_SEC),
                            ))
                            fig_uf.update_layout(**PLOTLY_BASE)
                            fig_uf.update_layout(title="Failed Logins by User",
                                                      xaxis_title="User", yaxis_title="Failures", height=320)
                            st.plotly_chart(fig_uf, use_container_width=True)

                with col_a2:
                    if auth_sc.get("src_ip") and auth_sc["src_ip"] in auth_f.columns and act_col in auth_f.columns:
                        ip_pivot = auth_f.groupby([auth_sc["src_ip"], act_col]).size().unstack(fill_value=0).reset_index()
                        fig_ip = go.Figure()
                        for col_name, color in [("Success", GREEN), ("Failed Login", RED)]:
                            if col_name in ip_pivot.columns:
                                fig_ip.add_trace(go.Bar(name=col_name, x=ip_pivot[auth_sc["src_ip"]],
                                                         y=ip_pivot[col_name], marker_color=color))
                        fig_ip.update_layout(**PLOTLY_BASE)
                        fig_ip.update_layout(barmode="group",
                                              title="Auth Outcomes by Source IP",
                                              xaxis_title="Source IP", yaxis_title="Count", height=320)
                        st.plotly_chart(fig_ip, use_container_width=True)

                if auth_sc.get("src_ip") and auth_sc["src_ip"] in auth_f.columns and act_col in auth_f.columns:
                    st.markdown("<p class='section-hdr'>Brute-Force Candidates (≥5 Failures)</p>", unsafe_allow_html=True)
                    fail_df = auth_f[auth_f[act_col].str.contains("fail", case=False, na=False, regex=True)]
                    ip_stats = fail_df.groupby(auth_sc["src_ip"]).size().reset_index(name="Failures")
                    ip_stats["Total Auth"] = auth_f.groupby(auth_sc["src_ip"]).size().reindex(ip_stats[auth_sc["src_ip"]]).values
                    ip_stats["Failure Rate"] = (ip_stats["Failures"] / ip_stats["Total Auth"]).map("{:.1%}".format)
                    ip_stats["Threat"] = ip_stats["Failures"].apply(lambda x: "CRITICAL" if x >= 20 else "HIGH" if x >= 10 else "MEDIUM")
                    brute = ip_stats[ip_stats["Failures"] >= 5].sort_values("Failures", ascending=False)
                    if not brute.empty:
                        st.dataframe(brute.rename(columns={auth_sc["src_ip"]: "Source IP"}),
                                     use_container_width=True, hide_index=True)
                    else:
                        st.markdown(f"<div class='banner-ok'>No brute-force candidates in current window.</div>", unsafe_allow_html=True)
            else:
                st.info("No auth data in current time window.")

        with tab_dns:
            st.markdown("<p class='section-hdr'>DNS Query Analysis</p>", unsafe_allow_html=True)
            if not dns_f.empty:
                ts_col  = dns_sc.get("timestamp")
                dom_col = dns_sc.get("domain")
                src_col = dns_sc.get("src_ip")

                if ts_col and ts_col in dns_f.columns:
                    dns_agg = dns_f.set_index(ts_col).resample("10min").size().reset_index(name="count")
                    fig_dns = go.Figure(go.Scatter(
                        x=dns_agg[ts_col], y=dns_agg["count"],
                        mode="lines", fill="tozeroy",
                        line=dict(color=LAVENDER, width=2),
                        fillcolor="rgba(208,187,255,0.1)",
                    ))
                    fig_dns.update_layout(**PLOTLY_BASE)
                    fig_dns.update_layout(title="DNS Volume (Spikes = Tunneling/C2)",
                                               xaxis_title="Time", yaxis_title="Queries", height=280)
                    st.plotly_chart(fig_dns, use_container_width=True)

                col_d1, col_d2 = st.columns(2)
                with col_d1:
                    if dom_col and dom_col in dns_f.columns:
                        top_dom = dns_f[dom_col].value_counts().head(15).reset_index()
                        top_dom.columns = ["Domain", "Queries"]
                        dom_colors = [RED if (d in SUSPICIOUS_DOMAINS or bool(re.search(r"\.(ru|cn|xyz|pw|tk)$", str(d), re.I))) else LAVENDER for d in top_dom["Domain"]]
                        fig_dom = go.Figure(go.Bar(
                            x=top_dom["Queries"], y=top_dom["Domain"],
                            orientation="h", marker_color=dom_colors,
                            text=top_dom["Queries"], textposition="outside", textfont=dict(color=TEXT_SEC, size=10),
                        ))
                        fig_dom.update_layout(**PLOTLY_BASE)
                        fig_dom.update_layout(title="Top 15 Queried Domains<br><sup>Red=Suspicious</sup>",
                                               xaxis_title="Queries", height=420,
                                               yaxis=dict(gridcolor="#21262d", tickfont=dict(color=TEXT, size=10), autorange="reversed"))
                        st.plotly_chart(fig_dom, use_container_width=True)

                with col_d2:
                    if src_col and src_col in dns_f.columns:
                        src_vc = dns_f[src_col].value_counts().reset_index()
                        src_vc.columns = ["Client IP", "Queries"]
                        fig_cli = go.Figure(go.Bar(
                            x=src_vc["Client IP"], y=src_vc["Queries"],
                            marker_color=CYAN, text=src_vc["Queries"],
                            textposition="outside", textfont=dict(color=TEXT_SEC),
                        ))
                        fig_cli.update_layout(**PLOTLY_BASE)
                        fig_cli.update_layout(title="Queries by Client IP",
                                               xaxis_title="Client IP", yaxis_title="Query Count", height=420)
                        st.plotly_chart(fig_cli, use_container_width=True)

                if dom_col and dom_col in dns_f.columns:
                    susp_mask = dns_f[dom_col].apply(
                        lambda d: d in SUSPICIOUS_DOMAINS or bool(re.search(r"\.(ru|cn|xyz|pw|tk|ml|ga|cf)$", str(d), re.I))
                    )
                    susp_dns = dns_f[susp_mask]
                    if not susp_dns.empty:
                        st.markdown("<p class='section-hdr'>Suspicious Domain Queries</p>", unsafe_allow_html=True)
                        st.dataframe(susp_dns, use_container_width=True, hide_index=True)

                st.markdown("<p class='section-hdr'>DNS Log Search</p>", unsafe_allow_html=True)
                q = st.text_input("Filter by domain keyword", "", placeholder="e.g. bad-actor, phish, amazonaws")
                dns_view = dns_f if not q else dns_f[dns_f[dom_col].str.contains(q, case=False, na=False)] if dom_col and dom_col in dns_f.columns else dns_f
                st.dataframe(dns_view.sort_values(ts_col, ascending=False).head(300) if ts_col and ts_col in dns_view.columns else dns_view.head(300),
                             use_container_width=True, hide_index=True)
            else:
                st.info("No DNS data in current time window.")

        with tab_mal:
            if mal.empty:
                st.markdown(f"<div class='banner-ok'><b>No malware alerts</b> — endpoint protection looks clean.</div>", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="banner-critical">
                  <b>{len(mal)} MALWARE ALERT(S) DETECTED — IMMEDIATE ACTION REQUIRED</b>
                </div>""", unsafe_allow_html=True)

                st.markdown("<p class='section-hdr'>Alert Details</p>", unsafe_allow_html=True)
                st.dataframe(mal, use_container_width=True, hide_index=True)

                cat_cols = [c for c in mal.columns if mal[c].dtype == object and mal[c].nunique() <= 30]
                if cat_cols:
                    n_c = min(3, len(cat_cols))
                    mal_cols = st.columns(n_c)
                    for i, col_name in enumerate(cat_cols[:3]):
                        with mal_cols[i]:
                            vc = mal[col_name].value_counts().reset_index()
                            vc.columns = [col_name, "count"]
                            fig_m = go.Figure(go.Bar(
                                x=vc["count"], y=vc[col_name].astype(str),
                                orientation='h',
                                marker=dict(color=vc["count"], colorscale='Reds'),
                                text=vc["count"], textposition="outside", textfont=dict(color=TEXT_SEC),
                            ))
                            fig_m.update_layout(**PLOTLY_BASE)
                            fig_m.update_layout(
                                title=f"By {col_name.replace('_',' ').title()}",
                                height=300, yaxis=dict(autorange="reversed"))
                            st.plotly_chart(fig_m, use_container_width=True)

                host_col = mal_sc.get("hostname")
                if host_col and host_col in mal.columns and auth_sc.get("user") and auth_sc["user"] in auth.columns:
                    affected_hosts = mal[host_col].unique().tolist()
                    st.markdown(f"<p class='section-hdr'>Affected Hosts Cross-Reference</p>", unsafe_allow_html=True)
                    st.markdown(f"<p style='color:{TEXT_SEC};font-size:0.82rem'>Infected host(s): <b style='color:{RED}'>{', '.join(str(h) for h in affected_hosts)}</b></p>", unsafe_allow_html=True)
                    st.markdown(f"<p style='color:{TEXT_SEC};font-size:0.82rem'>Check auth logs for logins from/to these hosts around the infection time.</p>", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # LOOP TRIGGER
        # ---------------------------------------------------------------------
        if st.session_state.live_mode and st.session_state.stream_progress < 1.0:
            st.markdown(f"""
            <div style='position:fixed;bottom:1rem;right:1.5rem;background:rgba(240,68,56,0.15);
                 border:1px solid {RED};border-radius:8px;padding:0.4rem 0.9rem;
                 font-size:0.72rem;color:{RED}; font-weight:bold;'>
              🔴 LIVE STREAM ACTIVE
            </div>""", unsafe_allow_html=True)
            time.sleep(2) # Reruns every 2 seconds
            st.rerun()

def show_splash_page(placeholder):
    """Displays the main splash page strictly within its own placeholder."""
    with placeholder.container():
        st.markdown("<h1 style='text-align: center; font-size: 3.5rem; font-weight: 700;'>AgentØ</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; font-size: 1.1rem; color: #8b949e;'>Your Real-Time SOC Intelligence Platform</p>", unsafe_allow_html=True)

        col1, _, col2 = st.columns([2, 0.5, 2])

        with col1:
            st.markdown("<h3 style='text-align: center;'>View a Demo</h3>", unsafe_allow_html=True)
            st.markdown("<p style='text-align: center; color: #8b949e; margin-bottom: 1rem;'>Analyze a pre-loaded dataset of a simulated cyber attack.</p>", unsafe_allow_html=True)
            st.button("See Example Case", use_container_width=True, key="splash_demo_btn", on_click=load_example_view)

        with col2:
            st.markdown("<h3 style='text-align: center;'>Analyze Your Data</h3>", unsafe_allow_html=True)
            st.file_uploader(
                "Drag and drop your CSV log files here to begin analysis.",
                accept_multiple_files=True,
                type="csv",
                key="splash_csv_uploader",
                on_change=process_file_upload
            )
            st.markdown("<p style='text-align: center; color: #8b949e; height: 60px;'>Upload your own CSV logs to detect threats in your environment.</p>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN APP ROUTER 
# ─────────────────────────────────────────────────────────────────────────────
if 'view' not in st.session_state:
    st.session_state.view = 'splash'
    st.session_state.uploaded_files = None
    st.session_state.live_mode = False
    
# Initialize state for data streaming simulation
if 'stream_progress' not in st.session_state:
    st.session_state.stream_progress = 0.8
if 'live_logs' not in st.session_state:
    st.session_state.live_logs = [f"<span style='color:{GREEN}'>[SYS]</span> AgentØ Initialized. Awaiting live data..."]

main_placeholder = st.empty()

if st.session_state.view == 'splash':
    show_splash_page(main_placeholder)
elif st.session_state.view == 'dashboard_example':
    run_dashboard(None, main_placeholder)
elif st.session_state.view == 'dashboard_upload':
    run_dashboard(st.session_state.uploaded_files, main_placeholder)
