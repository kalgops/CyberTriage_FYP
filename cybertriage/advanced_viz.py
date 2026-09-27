"""Advanced visualization components for CyberTriage.

Provides enhanced charts, heatmaps, network graphs, and analytics visualizations.
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Optional
import numpy as np


def create_threat_heatmap(df: pd.DataFrame) -> Optional[go.Figure]:
    """Create a heatmap showing threat activity by hour and IP."""
    if df.empty or 'timestamp' not in df.columns:
        return None
    
    # Extract hour from timestamp
    df_copy = df.copy()
    df_copy['hour'] = df_copy['timestamp'].str.extract(r'(\d{2}:\d{2})')[0]
    
    # Create pivot table
    pivot_data = df_copy.groupby(['source_ip', 'hour']).size().reset_index(name='count')
    
    if pivot_data.empty:
        return None
    
    # Create heatmap
    fig = go.Figure(data=go.Heatmap(
        z=pivot_data['count'],
        x=pivot_data['hour'],
        y=pivot_data['source_ip'],
        colorscale=[
            [0, '#10b981'],
            [0.5, '#f59e0b'],
            [1, '#ef4444']
        ],
        hoverongaps=False,
        hovertemplate='IP: %{y}<br>Time: %{x}<br>Events: %{z}<extra></extra>'
    ))
    
    fig.update_layout(
        title="Threat Activity Heatmap",
        xaxis_title="Time",
        yaxis_title="Source IP",
        height=400,
        template="plotly_dark",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
    )
    
    return fig


def create_attack_pattern_radar(detection: Dict) -> Optional[go.Figure]:
    """Create radar chart showing attack pattern characteristics."""
    top = detection.get("top_offender")
    if not top:
        return None
    
    # Calculate normalized metrics (0-100 scale)
    metrics = {
        'Failed Attempts': min(top.get('failed_count', 0) * 5, 100),
        'Username Diversity': min(top.get('username_count', 0) * 20, 100),
        'Persistence': 75 if top.get('failed_count', 0) > 10 else 40,
        'Velocity': min(detection.get('total_failed', 0) * 3, 100),
        'Severity Score': {'High': 95, 'Medium': 65, 'Low': 35, 'None': 10}.get(top.get('severity', 'None'), 10)
    }
    
    categories = list(metrics.keys())
    values = list(metrics.values())
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        fillcolor='rgba(102, 126, 234, 0.3)',
        line=dict(color='#667eea', width=3),
        marker=dict(size=8, color='#667eea'),
        name='Attack Profile'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 100],
                gridcolor='rgba(255,255,255,0.2)',
                tickfont=dict(color='white')
            ),
            angularaxis=dict(
                gridcolor='rgba(255,255,255,0.2)',
                tickfont=dict(color='white', size=11)
            ),
            bgcolor='rgba(0,0,0,0)'
        ),
        showlegend=False,
        title="Attack Pattern Analysis",
        height=450,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    
    return fig


def create_event_distribution_pie(df: pd.DataFrame) -> Optional[go.Figure]:
    """Create pie chart showing distribution of event types."""
    if df.empty or 'event_type' not in df.columns:
        return None
    
    event_counts = df['event_type'].value_counts()
    
    colors = {
        'failed_login': '#ef4444',
        'invalid_user': '#f59e0b',
        'successful_login': '#10b981',
        'unknown': '#6b7280'
    }
    
    fig = go.Figure(data=[go.Pie(
        labels=[label.replace('_', ' ').title() for label in event_counts.index],
        values=event_counts.values,
        hole=0.4,
        marker=dict(
            colors=[colors.get(event, '#6b7280') for event in event_counts.index],
            line=dict(color='white', width=2)
        ),
        textfont=dict(size=14, color='white'),
        hovertemplate='%{label}<br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )])
    
    fig.update_layout(
        title="Event Type Distribution",
        height=400,
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        showlegend=True,
        legend=dict(
            font=dict(color='white'),
            bgcolor='rgba(30, 41, 59, 0.8)',
            bordercolor='rgba(255,255,255,0.2)',
            borderwidth=1
        )
    )
    
    return fig


def create_ip_reputation_chart(detection: Dict) -> Optional[go.Figure]:
    """Create bar chart showing IP reputation scores."""
    ip_summaries = detection.get('ip_summaries', [])
    if not ip_summaries:
        return None
    
    # Calculate reputation scores (inverse of threat)
    ips = []
    scores = []
    colors = []
    
    for summary in ip_summaries[:10]:  # Top 10 IPs
        ips.append(summary['source_ip'])
        
        # Score based on severity (inverted - lower is worse)
        severity_score = {
            'High': 10,
            'Medium': 40,
            'Low': 70,
            'None': 100
        }.get(summary.get('severity', 'None'), 100)
        
        scores.append(severity_score)
        
        # Color based on score
        if severity_score < 30:
            colors.append('#ef4444')
        elif severity_score < 60:
            colors.append('#f59e0b')
        elif severity_score < 80:
            colors.append('#3b82f6')
        else:
            colors.append('#10b981')
    
    fig = go.Figure(data=[
        go.Bar(
            x=ips,
            y=scores,
            marker=dict(
                color=colors,
                line=dict(color='white', width=1.5)
            ),
            text=[f"{score}/100" for score in scores],
            textposition='outside',
            hovertemplate='IP: %{x}<br>Reputation: %{y}/100<extra></extra>'
        )
    ])
    
    fig.update_layout(
        title="IP Reputation Scores",
        xaxis_title="Source IP Address",
        yaxis_title="Reputation Score (0-100)",
        yaxis=dict(range=[0, 110]),
        height=400,
        template="plotly_dark",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    
    return fig


def create_feature_importance_chart(features: pd.DataFrame) -> Optional[go.Figure]:
    """Create chart showing ML feature importance."""
    if features.empty:
        return None
    
    # Calculate feature statistics
    feature_cols = ['failed_count', 'successful_count', 'unique_usernames', 
                   'events_per_minute', 'failure_ratio']
    
    importance = {}
    for col in feature_cols:
        if col in features.columns:
            # Use variance as proxy for importance
            importance[col.replace('_', ' ').title()] = features[col].var()
    
    if not importance:
        return None
    
    # Normalize to 0-100
    max_val = max(importance.values()) if importance.values() else 1
    importance = {k: (v / max_val * 100) if max_val > 0 else 0 
                 for k, v in importance.items()}
    
    fig = go.Figure(data=[
        go.Bar(
            x=list(importance.keys()),
            y=list(importance.values()),
            marker=dict(
                color=list(importance.values()),
                colorscale='Viridis',
                line=dict(color='white', width=1.5)
            ),
            text=[f"{v:.1f}%" for v in importance.values()],
            textposition='outside',
            hovertemplate='Feature: %{x}<br>Importance: %{y:.1f}%<extra></extra>'
        )
    ])
    
    fig.update_layout(
        title="ML Feature Importance",
        xaxis_title="Feature",
        yaxis_title="Relative Importance (%)",
        height=400,
        template="plotly_dark",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    
    return fig


def create_time_series_analysis(df: pd.DataFrame) -> Optional[go.Figure]:
    """Create time series showing event frequency over time."""
    if df.empty or 'timestamp' not in df.columns:
        return None
    
    df_copy = df.copy()
    
    # Group by timestamp and event type
    time_counts = df_copy.groupby(['timestamp', 'event_type']).size().reset_index(name='count')
    
    fig = go.Figure()
    
    event_colors = {
        'failed_login': '#ef4444',
        'invalid_user': '#f59e0b',
        'successful_login': '#10b981',
        'unknown': '#6b7280'
    }
    
    for event_type in time_counts['event_type'].unique():
        event_data = time_counts[time_counts['event_type'] == event_type]
        
        fig.add_trace(go.Scatter(
            x=event_data['timestamp'],
            y=event_data['count'],
            mode='lines+markers',
            name=event_type.replace('_', ' ').title(),
            line=dict(
                color=event_colors.get(event_type, '#6b7280'),
                width=3
            ),
            marker=dict(size=8),
            hovertemplate='Time: %{x}<br>Count: %{y}<extra></extra>'
        ))
    
    fig.update_layout(
        title="Event Frequency Timeline",
        xaxis_title="Timestamp",
        yaxis_title="Event Count",
        height=400,
        template="plotly_dark",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        hovermode='x unified',
        legend=dict(
            font=dict(color='white'),
            bgcolor='rgba(30, 41, 59, 0.8)',
            bordercolor='rgba(255,255,255,0.2)',
            borderwidth=1
        )
    )
    
    return fig


def create_ml_confidence_gauge(comparison: pd.DataFrame) -> Optional[go.Figure]:
    """Create gauge showing ML model confidence."""
    if comparison.empty or 'anomaly_score' not in comparison.columns:
        return None
    
    # Calculate average confidence (inverse of anomaly score)
    avg_score = comparison['anomaly_score'].mean()
    confidence = max(0, min(100, (1 - avg_score) * 100))
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=confidence,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "ML Model Confidence", 'font': {'size': 20, 'color': 'white'}},
        delta={'reference': 80, 'increasing': {'color': "#10b981"}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
            'bar': {'color': "#667eea", 'thickness': 0.75},
            'bgcolor': "rgba(0,0,0,0)",
            'borderwidth': 2,
            'bordercolor': "white",
            'steps': [
                {'range': [0, 40], 'color': 'rgba(239, 68, 68, 0.3)'},
                {'range': [40, 70], 'color': 'rgba(245, 158, 11, 0.3)'},
                {'range': [70, 100], 'color': 'rgba(16, 185, 129, 0.3)'}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 4},
                'thickness': 0.75,
                'value': confidence
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


def create_statistics_summary(df: pd.DataFrame, detection: Dict) -> Dict[str, any]:
    """Generate comprehensive statistics summary."""
    stats = {
        'total_events': len(df) if not df.empty else 0,
        'unique_ips': df['source_ip'].nunique() if not df.empty and 'source_ip' in df.columns else 0,
        'unique_users': df['username'].nunique() if not df.empty and 'username' in df.columns else 0,
        'failed_attempts': detection.get('total_failed', 0),
        'success_rate': 0,
        'threat_ips': len(detection.get('flagged_ips', [])),
        'avg_attempts_per_ip': 0,
        'peak_activity_time': 'N/A'
    }
    
    if not df.empty:
        # Calculate success rate
        successful = len(df[df['event_type'] == 'successful_login'])
        total_auth = stats['failed_attempts'] + successful
        stats['success_rate'] = (successful / total_auth * 100) if total_auth > 0 else 0
        
        # Average attempts per IP
        if stats['unique_ips'] > 0:
            stats['avg_attempts_per_ip'] = stats['total_events'] / stats['unique_ips']
        
        # Peak activity time
        if 'timestamp' in df.columns:
            time_counts = df['timestamp'].value_counts()
            if not time_counts.empty:
                stats['peak_activity_time'] = time_counts.index[0]
    
    return stats
