"""CyberTriage - Modern AI-Assisted Security Analytics Dashboard

AI-Assisted Cybersecurity Log Triage and Incident Explanation System.
Completely redesigned with modern UI/UX and interactive visualizations.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time

from cybertriage import anomaly, classifier, detector, parser, report, sample_data
from cybertriage.synthetic_dataset import generate_scenarios

# Page Configuration
st.set_page_config(
    page_title="CyberTriage - AI Security Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for modern design
st.markdown("""
<style>
    /* Main theme colors */
    :root {
        --primary-color: #1e3a8a;
        --secondary-color: #3b82f6;
        --success-color: #10b981;
        --warning-color: #f59e0b;
        --danger-color: #ef4444;
        --dark-bg: #0f172a;
        --card-bg: #1e293b;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Custom header styling */
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    }
    
    .main-title {
        color: white;
        font-size: 3rem;
        font-weight: 800;
        margin: 0;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .subtitle {
        color: rgba(255,255,255,0.9);
        font-size: 1.2rem;
        margin-top: 0.5rem;
    }
    
    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        margin: 0.5rem 0;
        transition: transform 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.3);
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
        color: white;
        margin: 0;
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: rgba(255,255,255,0.8);
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Alert boxes */
    .alert-critical {
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #7f1d1d;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(220, 38, 38, 0.3);
    }
    
    .alert-warning {
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #92400e;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(245, 158, 11, 0.3);
    }
    
    .alert-success {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #065f46;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
    }
    
    .alert-info {
        background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #1e40af;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    }
    
    /* Section headers */
    .section-header {
        font-size: 1.8rem;
        font-weight: 700;
        color: #1e293b;
        margin: 2rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 3px solid #667eea;
    }
    
    /* Custom buttons */
    .stButton>button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
    }
    
    /* Data tables */
    .dataframe {
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
    }
    
    /* Stats badge */
    .stats-badge {
        display: inline-block;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        margin: 0.25rem;
    }
    
    .badge-high {
        background: #fee2e2;
        color: #991b1b;
    }
    
    .badge-medium {
        background: #fef3c7;
        color: #92400e;
    }
    
    .badge-low {
        background: #dbeafe;
        color: #1e40af;
    }
    
    .badge-normal {
        background: #d1fae5;
        color: #065f46;
    }
</style>
""", unsafe_allow_html=True)

# Severity -> Alert style mapping
_SEVERITY_STYLE = {
    "High": "critical",
    "Medium": "warning",
    "Low": "info",
    "Informational": "info",
}

def _init_state() -> None:
    """Initialize session state defaults."""
    if "log_text" not in st.session_state:
        st.session_state.log_text = ""
    if "analysis_complete" not in st.session_state:
        st.session_state.analysis_complete = False

def _load_sample(name: str) -> None:
    """Load a bundled sample log into the text area."""
    st.session_state.log_text = sample_data.load_sample(name)
    st.session_state.analysis_complete = False

@st.cache_resource
def load_anomaly_model() -> anomaly.IsolationForestBaseline:
    """Train the reproducible model from normal reference scenarios once."""
    frames = []
    for scenario in generate_scenarios():
        if scenario.split == "train_normal":
            frames.append(anomaly.aggregate_features(parser.parse_log_text(scenario.log_text)))
    training = pd.concat(frames, ignore_index=True)
    return anomaly.IsolationForestBaseline(contamination=0.1, random_state=3070).fit(training)

def render_header() -> None:
    """Render modern header with gradient background."""
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">🛡️ CyberTriage</h1>
        <p class="subtitle">AI-Assisted Security Analytics & Incident Triage Platform</p>
    </div>
    """, unsafe_allow_html=True)

def render_metrics_cards(report_obj: dict, detection: dict) -> None:
    """Render modern metric cards with gradients."""
    top = report_obj.get("top_offender")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity = report_obj["severity"]
        severity_color = {
            "High": "#ef4444",
            "Medium": "#f59e0b",
            "Low": "#3b82f6",
            "Informational": "#10b981"
        }.get(severity, "#6b7280")
        
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, {severity_color} 0%, {severity_color}dd 100%); 
                    padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
            <div style="color: rgba(255,255,255,0.8); font-size: 0.9rem; text-transform: uppercase; 
                        letter-spacing: 1px; margin-bottom: 0.5rem;">Severity Level</div>
            <div style="color: white; font-size: 2rem; font-weight: bold;">{severity}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        failed_count = top["failed_count"] if top else detection["total_failed"]
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); 
                    padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
            <div style="color: rgba(255,255,255,0.8); font-size: 0.9rem; text-transform: uppercase; 
                        letter-spacing: 1px; margin-bottom: 0.5rem;">Failed Logins</div>
            <div style="color: white; font-size: 2rem; font-weight: bold;">{failed_count}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        source_ip = top["source_ip"] if top else "-"
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%); 
                    padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
            <div style="color: rgba(255,255,255,0.8); font-size: 0.9rem; text-transform: uppercase; 
                        letter-spacing: 1px; margin-bottom: 0.5rem;">Source IP</div>
            <div style="color: white; font-size: 1.5rem; font-weight: bold;">{source_ip}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        targeted_users = top["username_count"] if top else 0
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #ec4899 0%, #db2777 100%); 
                    padding: 1.5rem; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
            <div style="color: rgba(255,255,255,0.8); font-size: 0.9rem; text-transform: uppercase; 
                        letter-spacing: 1px; margin-bottom: 0.5rem;">Targeted Users</div>
            <div style="color: white; font-size: 2rem; font-weight: bold;">{targeted_users}</div>
        </div>
        """, unsafe_allow_html=True)

def create_timeline_chart(df: pd.DataFrame) -> go.Figure:
    """Create interactive timeline of authentication events."""
    if df.empty:
        return None
    
    df_copy = df.copy()
    df_copy['event_color'] = df_copy['event_type'].map({
        'failed_login': '#ef4444',
        'invalid_user': '#f59e0b',
        'successful_login': '#10b981',
        'unknown': '#6b7280'
    })
    
    fig = go.Figure()
    
    for event_type in df_copy['event_type'].unique():
        df_event = df_copy[df_copy['event_type'] == event_type]
        fig.add_trace(go.Scatter(
            x=list(range(len(df_event))),
            y=df_event['source_ip'],
            mode='markers',
            name=event_type.replace('_', ' ').title(),
            marker=dict(
                size=12,
                color=df_event['event_color'].iloc[0],
                line=dict(width=2, color='white')
            ),
            text=df_event['username'],
            hovertemplate='<b>%{y}</b><br>User: %{text}<br><extra></extra>'
        ))
    
    fig.update_layout(
        title="Authentication Events Timeline",
        xaxis_title="Event Sequence",
        yaxis_title="Source IP",
        height=400,
        template="plotly_dark",
        hovermode='closest',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
    )
    
    return fig

def create_severity_gauge(severity: str) -> go.Figure:
    """Create a gauge chart for severity visualization."""
    severity_value = {
        "Informational": 25,
        "Low": 40,
        "Medium": 70,
        "High": 95
    }.get(severity, 0)
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=severity_value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Level", 'font': {'size': 24, 'color': 'white'}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
            'bar': {'color': "#667eea"},
            'bgcolor': "rgba(0,0,0,0)",
            'borderwidth': 2,
            'bordercolor': "white",
            'steps': [
                {'range': [0, 30], 'color': '#10b981'},
                {'range': [30, 60], 'color': '#3b82f6'},
                {'range': [60, 80], 'color': '#f59e0b'},
                {'range': [80, 100], 'color': '#ef4444'}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 4},
                'thickness': 0.75,
                'value': severity_value
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': "white", 'family': "Arial"}
    )
    
    return fig

def create_model_comparison_chart(comparison: pd.DataFrame) -> go.Figure:
    """Create comparison chart for rule vs ML model."""
    if comparison.empty:
        return None
    
    fig = go.Figure()
    
    # Rule-based results
    fig.add_trace(go.Bar(
        name='Rule-Based Detection',
        x=comparison['source_ip'],
        y=comparison['rule_flagged'].astype(int),
        marker_color='#667eea',
        text=comparison['rule_flagged'].map({True: 'Suspicious', False: 'Normal'}),
        textposition='auto',
    ))
    
    # Isolation Forest results
    fig.add_trace(go.Bar(
        name='Isolation Forest',
        x=comparison['source_ip'],
        y=comparison['isolation_forest_anomaly'].astype(int),
        marker_color='#ec4899',
        text=comparison['isolation_forest_anomaly'].map({True: 'Anomaly', False: 'Normal'}),
        textposition='auto',
    ))
    
    fig.update_layout(
        title="Detection Model Comparison",
        xaxis_title="Source IP Address",
        yaxis_title="Detection Result",
        barmode='group',
        height=400,
        template="plotly_dark",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
    )
    
    return fig

def render_inputs() -> str:
    """Render modern input section with sample buttons."""
    st.markdown('<h2 class="section-header">📥 Log Input</h2>', unsafe_allow_html=True)
    
    # Sample buttons in a nice grid
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🟢 Normal Activity", use_container_width=True):
            _load_sample("normal")
            st.rerun()
    
    with col2:
        if st.button("🔴 Brute Force Attack", use_container_width=True):
            _load_sample("brute_force")
            st.rerun()
    
    with col3:
        if st.button("🟡 Mixed Activity", use_container_width=True):
            _load_sample("mixed")
            st.rerun()
    
    st.markdown("---")
    
    # File uploader
    uploaded = st.file_uploader(
        "📁 Upload SSH Log File (.log or .txt)",
        type=["log", "txt"],
        accept_multiple_files=False,
        help="Upload your SSH authentication log file for analysis"
    )
    
    if uploaded is not None:
        st.session_state.log_text = uploaded.read().decode("utf-8", errors="replace")
        st.session_state.analysis_complete = False
    
    # Text area for manual input
    log_text = st.text_area(
        "📝 Or paste SSH authentication log lines here",
        value=st.session_state.log_text,
        height=250,
        key="log_text",
        placeholder="Jun 10 10:01:22 server sshd[1122]: Failed password for root from 192.168.1.45 port 53422 ssh2\n...",
        help="Paste your SSH authentication logs here for analysis"
    )
    
    return log_text

def render_results(log_text: str, use_llm: bool, model: str, host: str) -> None:
    """Render comprehensive analysis results with modern visualizations."""
    
    # Show loading animation
    with st.spinner("🔍 Analyzing logs..."):
        progress_bar = st.progress(0)
        for i in range(100):
            time.sleep(0.01)
            progress_bar.progress(i + 1)
        
        df = parser.parse_log_text(log_text)
        detection = detector.detect(df)
        report_obj = report.build_report(df, detection)
        features = anomaly.aggregate_features(df)
        model_obj = load_anomaly_model()
        comparison = anomaly.compare_with_rules(features, detection, model_obj)
    
    st.session_state.analysis_complete = True
    
    incident_type = report_obj["incident_type"]
    severity = report_obj["severity"]
    
    # Main alert banner
    st.markdown('<h2 class="section-header">🎯 Analysis Results</h2>', unsafe_allow_html=True)
    
    alert_class = f"alert-{_SEVERITY_STYLE.get(severity, 'info')}"
    st.markdown(f"""
    <div class="{alert_class}">
        <h2 style="margin: 0 0 0.5rem 0; font-size: 1.8rem;">
            {incident_type}
        </h2>
        <p style="margin: 0; font-size: 1.1rem; opacity: 0.9;">
            Severity: <strong>{severity}</strong> | 
            Total Events: <strong>{detection.get('total_events', 0)}</strong> | 
            Failed Logins: <strong>{detection.get('total_failed', 0)}</strong>
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Metrics cards
    render_metrics_cards(report_obj, detection)
    
    st.markdown("---")
    
    # Two column layout for visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<h3 class="section-header">📊 Threat Assessment</h3>', unsafe_allow_html=True)
        gauge_fig = create_severity_gauge(severity)
        st.plotly_chart(gauge_fig, use_container_width=True)
    
    with col2:
        st.markdown('<h3 class="section-header">📈 Event Timeline</h3>', unsafe_allow_html=True)
        if not df.empty:
            timeline_fig = create_timeline_chart(df)
            if timeline_fig:
                st.plotly_chart(timeline_fig, use_container_width=True)
        else:
            st.info("No events to display")
    
    st.markdown("---")
    
    # Model comparison
    st.markdown('<h2 class="section-header">🤖 AI Model Comparison</h2>', unsafe_allow_html=True)
    
    if comparison.empty:
        st.info("ℹ️ No source-IP features available for model comparison.")
    else:
        # Comparison chart
        comp_fig = create_model_comparison_chart(comparison)
        if comp_fig:
            st.plotly_chart(comp_fig, use_container_width=True)
        
        # Detailed comparison table
        with st.expander("📋 View Detailed Comparison Table", expanded=False):
            display = comparison[[
                "source_ip", "failed_count", "successful_count", "unique_usernames",
                "events_per_minute", "failure_ratio", "rule_flagged",
                "isolation_forest_anomaly", "anomaly_score", "model_status",
            ]].rename(columns={
                "source_ip": "Source IP", "failed_count": "Failed",
                "successful_count": "Successful", "unique_usernames": "Unique users",
                "events_per_minute": "Events/min", "failure_ratio": "Failure ratio",
                "rule_flagged": "Rule result", "isolation_forest_anomaly": "Isolation Forest result",
                "anomaly_score": "Anomaly score", "model_status": "Model status",
            })
            display["Rule result"] = display["Rule result"].map({True: "🔴 Suspicious", False: "🟢 Normal"})
            display["Isolation Forest result"] = display["Isolation Forest result"].map({True: "🔴 Anomaly", False: "🟢 Normal"})
            st.dataframe(display, use_container_width=True, hide_index=True)
            
            st.caption(f"ℹ️ Isolation Forest trained on {model_obj.training_rows} deterministic normal reference observations.")
    
    st.markdown("---")
    
    # Incident explanation
    st.markdown('<h2 class="section-header">💡 Incident Explanation</h2>', unsafe_allow_html=True)
    
    template_summary = report_obj["summary"]
    explanation = template_summary
    provenance = "Template-based explanation"
    
    if use_llm:
        with st.spinner("🤖 Generating AI explanation..."):
            llm_text = report.generate_llm_explanation(report_obj, model=model, host=host)
        if llm_text:
            explanation = llm_text
            provenance = "Generated by local Ollama LLM"
        else:
            explanation = template_summary
            provenance = "Template fallback (Ollama unavailable)"
    
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); 
                padding: 2rem; border-radius: 12px; border-left: 5px solid #667eea;
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
        <p style="color: white; font-size: 1.1rem; line-height: 1.8; margin: 0;">
            {explanation}
        </p>
        <p style="color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-top: 1rem; margin-bottom: 0;">
            <em>Source: {provenance}</em>
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Evidence summary
    st.markdown('<h2 class="section-header">🔍 Evidence Summary</h2>', unsafe_allow_html=True)
    
    evidence_cols = st.columns(len(report_obj["evidence"]))
    for idx, (key, value) in enumerate(report_obj["evidence"].items()):
        with evidence_cols[idx]:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #334155 0%, #1e293b 100%); 
                        padding: 1.5rem; border-radius: 10px; text-align: center;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.2);">
                <div style="color: rgba(255,255,255,0.7); font-size: 0.85rem; 
                            text-transform: uppercase; margin-bottom: 0.5rem;">
                    {key}
                </div>
                <div style="color: white; font-size: 1.3rem; font-weight: bold;">
                    {value}
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    # Time window
    top = report_obj.get("top_offender")
    if top and top["first_seen"]:
        st.info(f"⏱️ Time window: **{top['first_seen']}** to **{top['last_seen'] or top['first_seen']}**")
    
    st.markdown("---")
    
    # Per-IP detection breakdown
    if detection["ip_summaries"]:
        st.markdown('<h2 class="section-header">🌐 Per-IP Detection Breakdown</h2>', unsafe_allow_html=True)
        
        ip_df = pd.DataFrame([
            {
                "Source IP": s["source_ip"],
                "Failed": s["failed_count"],
                "Users": s["username_count"],
                "Usernames": ", ".join(s["unique_usernames"][:3]) + ("..." if len(s["unique_usernames"]) > 3 else ""),
                "First Seen": s["first_seen"],
                "Last Seen": s["last_seen"],
                "Severity": s["severity"],
                "Status": "🔴 Flagged" if s["flagged"] else "🟢 Normal",
            }
            for s in detection["ip_summaries"]
        ])
        
        st.dataframe(
            ip_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Severity": st.column_config.TextColumn(
                    "Severity",
                    help="Threat severity level"
                ),
                "Status": st.column_config.TextColumn(
                    "Status",
                    help="Detection status"
                )
            }
        )
    
    st.markdown("---")
    
    # Recommended actions
    st.markdown('<h2 class="section-header"> Recommended Actions</h2>', unsafe_allow_html=True)
    
    for idx, step in enumerate(report_obj["recommended_steps"], start=1):
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); 
                    padding: 1rem 1.5rem; border-radius: 8px; margin: 0.5rem 0;
                    border-left: 4px solid #667eea;">
            <strong style="color: #667eea; font-size: 1.1rem;">{idx}.</strong>
            <span style="color: white; margin-left: 0.5rem;">{step}</span>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Parsed log evidence
    with st.expander(" View Parsed Log Evidence", expanded=False):
        if df.empty:
            st.info("No parseable SSH log lines were found in the input.")
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)
    
    # Download report
    st.markdown('<h2 class="section-header"> Export Report</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        text_report = report.render_text_report(report_obj)
        st.download_button(
            "📄 Download Text Report",
            data=text_report,
            file_name=f"cybertriage_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )
    
    with col2:
        csv_data = df.to_csv(index=False)
        st.download_button(
            "📊 Download CSV Data",
            data=csv_data,
            file_name=f"cybertriage_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

def main() -> None:
    """Application entrypoint."""
    _init_state()
    
    # Sidebar configuration
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 1rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    border-radius: 10px; margin-bottom: 1rem;">
            <h2 style="color: white; margin: 0;">⚙️ Settings</h2>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### 🤖 AI Configuration")
        
        use_llm = st.checkbox(
            "Enable Ollama LLM",
            value=False,
            help="Use local Ollama for natural language explanations (optional)"
        )
        
        if use_llm:
            model = st.text_input(
                "Model Name",
                value=report.get_ollama_model(),
                help="Ollama model to use (e.g., llama3, mistral)"
            )
            
            host = st.text_input(
                "Ollama Host",
                value=report.get_ollama_host(),
                help="Ollama server URL"
            )
            
            # Check availability
            if report.ollama_available(model, host):
                st.success("✅ Ollama is available")
            else:
                st.warning("⚠️ Ollama unavailable - will use template fallback")
        else:
            model = report.get_ollama_model()
            host = report.get_ollama_host()
        
        st.markdown("---")
        
        st.markdown("### 📊 Detection Thresholds")
        st.info("""
        **Low:** 3-4 failed attempts  
        **Medium:** 5-9 failed attempts  
        **High:** 10+ failed attempts
        
        *Severity escalates when multiple usernames are targeted*
        """)
        
        st.markdown("---")
        
        st.markdown("### ℹ️ About")
        st.markdown("""
        **CyberTriage** is an AI-assisted security analytics platform for SSH log analysis.
        
        - 🔍 Intelligent threat detection
        - 🤖 ML-powered anomaly detection
        - 📊 Interactive visualizations
        - 📝 Automated incident reports
        
        *Educational prototype for defensive cybersecurity*
        """)
        
        st.markdown("---")
        st.caption("© 2026 CyberTriage | CM3070 Final Year Project")
    
    # Main content
    render_header()
    
    log_text = render_inputs()
    
    # Analyze button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        analyze_clicked = st.button("🔍 Analyze Logs", type="primary", use_container_width=True)
    
    if analyze_clicked:
        if not log_text.strip():
            st.warning("⚠️ Please provide logs to analyze (paste, upload, or load a sample)")
        else:
            render_results(log_text, use_llm, model, host)
    elif st.session_state.analysis_complete and log_text.strip():
        # Re-render results if already analyzed
        render_results(log_text, use_llm, model, host)

if __name__ == "__main__":
    main()
