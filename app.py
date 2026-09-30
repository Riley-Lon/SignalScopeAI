import streamlit as st
import pandas as pd
import ipaddress

from src.parser import load_csv
from src.detector import find_suspicious_events

from src.utils.scoring import (
    calculate_threat_score,
    get_threat_level,
    get_score_breakdown,
)

from src.utils.investigation import (
    build_summary,
    severity_breakdown,
    get_top_finding,
    build_timeline,
    build_detection_breakdown,
    build_highlights,
    build_investigation_context,
)

from src.utils.prompts import build_ai_prompt
from src.utils.report_export import build_download_report
from src.utils.session import initialize_session_state
from src.utils.pdf_report import build_pdf_report
from src.utils.threat_intel import check_ip_reputation

import ai_report

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="SignalScope AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# SESSION STATE
# ============================================================

initialize_session_state()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("⚙️ Investigation Settings")

audience = st.sidebar.selectbox(
    "Report Audience",
    [
        "SOC Analyst",
        "IT Manager",
        "Executive",
    ],
)

report_style = st.sidebar.radio(
    "Report Style",
    [
        "Brief",
        "Detailed",
    ],
)

st.sidebar.divider()

include_mitre = st.sidebar.checkbox(
    "Include MITRE ATT&CK",
    value=True,
)

include_recommendations = st.sidebar.checkbox(
    "Include Recommendations",
    value=True,
)

include_confidence = st.sidebar.checkbox(
    "Include Confidence Score",
    value=True,
)

st.sidebar.divider()

st.sidebar.caption("SignalScope AI v0.1")


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def reset_evidence_filters():
    """Reset all Evidence section filters."""

    st.session_state.evidence_severity_filter = "All"
    st.session_state.evidence_username_filter = "All"
    st.session_state.evidence_search = ""

# ============================================================
# HERO
# ============================================================

st.title(
    "🛡️ SignalScope AI"
)

st.caption(
    "AI Security Investigation Platform"
)

st.info(
    "💡 Configure your investigation using "
    "the settings in the left sidebar before "
    "uploading a security log."
)


# ============================================================
# UPLOAD
# ============================================================

st.header(
    "📂 Upload Security Log"
)

st.caption(
    "Upload a Windows Event Log, firewall log, "
    "authentication log, or CSV export to begin "
    "the investigation."
)

uploaded_file = st.file_uploader(
    "Upload a CSV security log",
    type=["csv"],
    label_visibility="collapsed",
)


# ============================================================
# INVESTIGATION
# ============================================================

if uploaded_file is not None:

    try:

        # ----------------------------------------------------
        # Identify current investigation
        # ----------------------------------------------------

        file_id = (
            f"{uploaded_file.name}_"
            f"{uploaded_file.size}"
        )

        if (
            st.session_state.current_file_id
            != file_id
        ):

            st.session_state.chat_messages = []

            st.session_state.generated_report = None

            st.session_state.pending_question = ""

            st.session_state.current_file_id = (
                file_id
            )

        # ----------------------------------------------------
        # Load and analyze
        # ----------------------------------------------------

        df = load_csv(
            uploaded_file
        )

        suspicious_df = (
            find_suspicious_events(df)
        )

        st.success(
            "File uploaded successfully."
        )

        # ----------------------------------------------------
        # Risk calculations
        # ----------------------------------------------------

        threat_score = (
            calculate_threat_score(
                suspicious_df
            )
        )

        threat_level = (
            get_threat_level(
                threat_score
            )
        )

        # ----------------------------------------------------
        # Metadata
        # ----------------------------------------------------

        scan_time = (
            pd.Timestamp.now().strftime(
                "%b %d, %Y %I:%M %p"
            )
        )

        st.caption(
            f"Audience: {audience}  •  "
            f"Style: {report_style}  •  "
            f"Last Scan: {scan_time}"
        )

        # ====================================================
        # INVESTIGATION OVERVIEW
        # ====================================================

        st.subheader(
            "📊 Investigation Overview"
        )

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "Threat Score",
                f"{threat_score}/100",
                help=(
                    "Deterministic risk score "
                    "calculated from suspicious "
                    "events."
                ),
            )

        with col2:

            if threat_level == "High":
                display_level = "🔴 High"

            elif threat_level == "Medium":
                display_level = "🟠 Medium"

            else:
                display_level = "🟢 Low"

            st.metric(
                "Threat Level",
                display_level,
            )

        with col3:

            st.metric(
                "Findings",
                len(suspicious_df),
            )

            # ----------------------------------------------------
        # Investigation risk summary
        # ----------------------------------------------------

        if threat_level == "High":
            risk_summary = (
                "High investigation risk. Multiple or strongly "
                "correlated suspicious behaviors were detected "
                "and should be prioritized for investigation."
            )

        elif threat_level == "Medium":
            risk_summary = (
                "Medium investigation risk. Meaningful suspicious "
                "behavior was detected, but the available evidence "
                "does not independently confirm compromise."
            )

        else:
            risk_summary = (
                "Low investigation risk. The available evidence "
                "contains limited suspicious behavior or isolated "
                "indicators that should be reviewed in context."
            )

        st.caption(
            risk_summary
        )

        # ----------------------------------------------------
        # Threat score breakdown
        # ----------------------------------------------------

        with st.expander(
            "📈 Why is this score?",
            expanded=False,
        ):

            score_breakdown = get_score_breakdown(
                suspicious_df
            )

            if score_breakdown:

                breakdown_df = pd.DataFrame(
                    score_breakdown,
                    columns=[
                        "Reason",
                        "Points",
                    ],
                )

                st.dataframe(
                    breakdown_df,
                    width="stretch",
                    hide_index=True,
                )

                st.caption(
                    "The threat score is calculated by "
                    "SignalScope's deterministic scoring "
                    "engine. The AI does not determine "
                    "this score."
                )

            else:

                st.info(
                    "No suspicious behaviors contributed "
                    "to the threat score."
                )

        # ====================================================
        # TOP FINDING
        # ====================================================

        st.subheader(
            "🚨 Top Finding"
        )

        top_finding = get_top_finding(
            suspicious_df
        )

        with st.container(
            border=True
        ):

            st.caption(
                "MOST IMPORTANT EVENT"
            )

            st.write(
                top_finding
            )

        # ====================================================
        # HIGHLIGHTS
        # ====================================================

        st.subheader(
            "📌 Investigation Highlights"
        )

        highlights_df = build_highlights(
            df,
            suspicious_df,
        )

        st.dataframe(
            highlights_df,
            width="stretch",
            hide_index=True,
        )

        # ====================================================
        # MAIN INVESTIGATION
        # ====================================================

        left, right = st.columns(
            [1.1, 0.9]
        )

        with left:

            with st.container(
                border=True
            ):

                st.subheader(
                    "📄 Uploaded Log"
                )

                st.dataframe(
                    df,
                    width="stretch",
                    hide_index=True,
                )

            st.write("")

            with st.container(
                border=True
            ):

                st.subheader(
                    "🚨 Incident Summary"
                )

                summary_text = (
                    build_summary(
                        suspicious_df
                    )
                )

                st.write(
                    summary_text
                )

            st.write("")

            with st.container(
                border=True
            ):

                st.subheader(
                    "🕒 Investigation Timeline"
                )

                timeline_df = (
                    build_timeline(
                        suspicious_df
                    )
                )

                if timeline_df.empty:

                    st.info(
                        "No suspicious timeline "
                        "events to show."
                    )

                else:

                    st.dataframe(
                        timeline_df,
                        width="stretch",
                        hide_index=True,
                    )

        with right:

            with st.container(
                border=True
            ):

                st.subheader(
                    "📊 Severity Breakdown"
                )

                if not suspicious_df.empty:

                    chart_df = (
                        severity_breakdown(
                            suspicious_df
                        )
                    )

                    st.bar_chart(
                        chart_df.set_index(
                            "Severity"
                        )
                    )

                else:

                    st.info(
                        "No suspicious events "
                        "were detected."
                    )

            st.write("")

            with st.container(
                border=True
            ):

                st.subheader(
                    "🧭 Detection Breakdown"
                )

                detection_df = (
                    build_detection_breakdown(
                        suspicious_df
                    )
                )

                if not detection_df.empty:

                    st.dataframe(
                        detection_df,
                        width="stretch",
                        hide_index=True,
                    )

                else:

                    st.info(
                        "No detection breakdown "
                        "available."
                    )

            st.write("")

            with st.container(
                border=True
            ):

                st.subheader(
                    "🔍 Evidence"
                )

                if not suspicious_df.empty:

                    # ------------------------------------------------
                    # Evidence filters
                    # ------------------------------------------------
                    if st.button(
                        "↩️ Reset Evidence Filters",
                        width="stretch",
                        on_click=reset_evidence_filters,
                    ):
                        pass
                    
                    filter_col1, filter_col2 = st.columns(2)

                    with filter_col1:

                        severity_options = [
                            "All",
                            "High",
                            "Medium",
                            "Low",
                        ]

                        selected_severity = st.selectbox(
                            "Severity",
                            severity_options,
                            key="evidence_severity_filter",
                        )

                    with filter_col2:

                        username_values = (
                            suspicious_df["username"]
                            .dropna()
                            .astype(str)
                            .drop_duplicates()
                            .sort_values()
                            .tolist()
                        )

                        username_options = [
                            "All"
                        ] + username_values

                        selected_username = st.selectbox(
                            "Username",
                            username_options,
                            key="evidence_username_filter",
                        )

                    evidence_search = st.text_input(
                        "Search evidence",
                        placeholder=(
                            "Search username, IP, action, "
                            "reason, or MITRE technique..."
                        ),
                        key="evidence_search",
                    )

                    filtered_evidence_df = (
                        suspicious_df.copy()
                    )

                    if selected_severity != "All":

                        filtered_evidence_df = (
                            filtered_evidence_df[
                                filtered_evidence_df[
                                    "severity"
                                ]
                                .astype(str)
                                == selected_severity
                            ]
                        )

                    if selected_username != "All":

                        filtered_evidence_df = (
                            filtered_evidence_df[
                                filtered_evidence_df[
                                    "username"
                                ]
                                .astype(str)
                                == selected_username
                            ]
                        )

                    if evidence_search.strip():

                        search_text = (
                            evidence_search
                            .strip()
                            .lower()
                        )

                        searchable_columns = [
                            column
                            for column in [
                                "username",
                                "source_ip",
                                "destination_ip",
                                "action",
                                "severity",
                                "mitre_technique",
                                "suspicion_reason",
                            ]
                            if column
                            in filtered_evidence_df.columns
                        ]

                        search_mask = (
                            filtered_evidence_df[
                                searchable_columns
                            ]
                            .astype(str)
                            .apply(
                                lambda column: column.str.lower()
                                .str.contains(
                                    search_text,
                                    na=False,
                                )
                            )
                            .any(axis=1)
                        )

                        filtered_evidence_df = (
                            filtered_evidence_df[
                                search_mask
                            ]
                        )

                    st.caption(
                        f"Showing {len(filtered_evidence_df)} "
                        f"of {len(suspicious_df)} suspicious findings."
                    )

                    display_cols = [
                        col
                        for col in [
                            "timestamp",
                            "event_id",
                            "username",
                            "source_ip",
                            "destination_ip",
                            "action",
                            "severity",
                            "mitre_technique",
                            "suspicion_reason",
                        ]
                        if col
                        in suspicious_df.columns
                    ]

                    st.dataframe(
                        filtered_evidence_df[
                            display_cols
                        ],
                        width="stretch",
                        hide_index=True,
                    )

                else:

                    st.info(
                        "No evidence to show "
                        "because no suspicious "
                        "events were detected."
                    )


        # ====================================================
        # AI INVESTIGATION
        # ====================================================

        st.write("")

        st.subheader(
            "🤖 AI Investigation"
        )

        with st.container(
            border=True
        ):

            st.caption(
                "AI SECURITY ANALYST"
            )

            st.write(
                f"Generate a {report_style.lower()} "
                f"investigation report for a "
                f"{audience.lower()}."
            )

            st.caption(
                "The AI analyzes the suspicious "
                "events identified by the "
                "SignalScope detection engine."
            )

        st.write("")

        generate_report = st.button(
            "🤖 Generate AI Analysis",
            type="primary",
            width="stretch",
        )

        if generate_report:

            with st.spinner(
                "SignalScope AI is analyzing "
                "the investigation..."
            ):

                suspicious_events_text = (
                    suspicious_df.to_string(
                        index=False
                    )
                )

                prompt = build_ai_prompt(
                    summary_text,
                    suspicious_events_text,
                    audience=audience,
                    report_style=report_style,
                    include_mitre=include_mitre,
                    include_recommendations=include_recommendations,
                    include_confidence=include_confidence,
                    threat_score=threat_score,
                    threat_level=threat_level,
                )

                st.session_state.generated_report = (
                    ai_report.generate_investigation_report(
                        prompt
                    )
                )

        # ----------------------------------------------------
        # Display persistent AI report
        # ----------------------------------------------------

        if st.session_state.generated_report:

            st.subheader(
                "📋 AI Investigation Report"
            )

            with st.container(
                border=True
            ):

                st.markdown(
                    st.session_state.generated_report
                )

        # ====================================================
        # ASK SIGNALSCOPE AI
        # ====================================================

        st.write("")

        st.subheader(
            "💬 Ask SignalScope AI"
        )

        st.caption(
            "Ask follow-up questions about "
            "the current investigation."
        )

        # ----------------------------------------------------
        # Conversation history
        # ----------------------------------------------------

        if st.session_state.chat_messages:

            st.write(
                "### Investigation Conversation"
            )

            for message in (
                st.session_state.chat_messages
            ):

                role = message.get(
                    "role",
                    "user",
                )

                content = message.get(
                    "content",
                    "",
                )

                if role == "user":

                    with st.chat_message(
                        "user"
                    ):

                        st.markdown(
                            content
                        )

                else:

                    with st.chat_message(
                        "assistant"
                    ):

                        st.markdown(
                            content
                        )

        else:

            st.info(
                "Start a conversation about "
                "this investigation. SignalScope "
                "will remember your previous "
                "questions and answers."
            )

        # ====================================================
        # QUICK QUESTIONS
        # ====================================================

        st.write(
            "**Quick questions:**"
        )

        quick_col1, quick_col2 = st.columns(2)

        with quick_col1:

            if st.button(
                "🚨 Why is this high risk?",
                width="stretch",
            ):

                st.session_state.pending_question = (
                    "Why is this considered high risk?"
                )

            if st.button(
                "📋 What should I investigate first?",
                width="stretch",
            ):

                st.session_state.pending_question = (
                    "What should I investigate first?"
                )

        with quick_col2:

            if st.button(
                "🔎 Could this be a false positive?",
                width="stretch",
            ):

                st.session_state.pending_question = (
                    "Could these findings be a false positive?"
                )

            if st.button(
                "💻 Explain the PowerShell finding",
                width="stretch",
            ):

                st.session_state.pending_question = (
                    "Explain the PowerShell finding."
                )

        # ----------------------------------------------------
        # Selected quick question
        # ----------------------------------------------------

        if st.session_state.pending_question:

            st.info(
                f"Selected question: "
                f"{st.session_state.pending_question}"
            )

        # ----------------------------------------------------
        # Question input
        # ----------------------------------------------------

        user_question = st.text_input(
            "Your question",
            value=st.session_state.pending_question,
            placeholder=(
                "Ask something about this investigation..."
            ),
            key="question_input",
        )

        ask_question = st.button(
            "💬 Ask SignalScope AI",
            width="stretch",
        )

        if ask_question:

            if not user_question.strip():

                st.warning(
                    "Please enter a question first."
                )

            else:

                investigation_context = (
                    build_investigation_context(
                        suspicious_df,
                        summary_text,
                        threat_score,
                        threat_level,
                    )
                )

                previous_history = (
                    st.session_state.chat_messages.copy()
                )

                st.session_state.chat_messages.append(
                    {
                        "role": "user",
                        "content": user_question,
                    }
                )

                with st.spinner(
                    "SignalScope AI is thinking..."
                ):

                    chat_answer = (
                        ai_report.ask_investigation_question(
                            user_question,
                            investigation_context,
                            conversation_history=previous_history,
                        )
                    )

                st.session_state.chat_messages.append(
                    {
                        "role": "assistant",
                        "content": chat_answer,
                    }
                )

                st.session_state.pending_question = ""

                st.rerun()

        # ----------------------------------------------------
        # Clear conversation
        # ----------------------------------------------------

        if st.session_state.chat_messages:

            if st.button(
                "🗑️ Clear Conversation"
            ):

                st.session_state.chat_messages = []

                st.session_state.pending_question = ""

                st.rerun()

        # ====================================================
        # THREAT INTELLIGENCE
        # ====================================================

        st.write("")

        st.subheader(
            "🌐 Threat Intelligence"
        )

        with st.container(
            border=True
        ):

            st.caption(
                "Enrich a suspicious public IP with external "
                "threat-intelligence context. This does not "
                "change SignalScope's deterministic threat score."
            )

            public_ips = []

            if "source_ip" in suspicious_df.columns:

                public_ips.extend(
                    suspicious_df[
                        "source_ip"
                    ]
                    .dropna()
                    .astype(str)
                    .tolist()
                )

            if "destination_ip" in suspicious_df.columns:

                public_ips.extend(
                    suspicious_df[
                        "destination_ip"
                    ]
                    .dropna()
                    .astype(str)
                    .tolist()
                )

            unique_ips = sorted(
                set(public_ips)
            )

            public_ips = []

            documentation_ranges = [
                ipaddress.ip_network(
                    "192.0.2.0/24"
                ),
                ipaddress.ip_network(
                    "198.51.100.0/24"
                ),
                ipaddress.ip_network(
                    "203.0.113.0/24"
                ),
            ]

            for ip in unique_ips:

                try:
                    parsed_ip = ipaddress.ip_address(
                        ip
                    )

                    is_documentation_ip = any(
                        parsed_ip in network
                        for network in documentation_ranges
                    )

                    if (
                        parsed_ip.is_global
                        or is_documentation_ip
                    ):
                        public_ips.append(
                            ip
                        )

                except ValueError:
                    continue
                           

            if public_ips:

                selected_ip = st.selectbox(
                    "IP address",
                    public_ips,
                    key="threat_intel_ip",
                )

                if st.button(
                    "🔎 Check IP Reputation",
                    width="stretch",
                ):

                    with st.spinner(
                        "Checking threat intelligence..."
                    ):

                        threat_intel_result = (
                            check_ip_reputation(
                                selected_ip
                            )
                        )

                    if (
                        threat_intel_result.get(
                            "success"
                        )
                    ):

                        st.success(
                            "Threat intelligence retrieved successfully."
                        )

                        result_col1, result_col2, result_col3 = (
                            st.columns(3)
                        )

                        with result_col1:

                            st.metric(
                                "Abuse Confidence",
                                (
                                    f"{threat_intel_result.get('abuse_confidence_score', 'N/A')}"
                                    "%"
                                ),
                            )

                        with result_col2:

                            st.metric(
                                "Reports",
                                threat_intel_result.get(
                                    "total_reports",
                                    "N/A",
                                ),
                            )

                        with result_col3:

                            st.metric(
                                "Whitelisted",
                                str(
                                    threat_intel_result.get(
                                        "is_whitelisted",
                                        "N/A",
                                    )
                                ),
                            )

                        intel_table = pd.DataFrame(
                            [
                                [
                                    "Country",
                                    threat_intel_result.get(
                                        "country_code",
                                        "N/A",
                                    ),
                                ],
                                [
                                    "ISP",
                                    threat_intel_result.get(
                                        "isp",
                                        "N/A",
                                    ),
                                ],
                                [
                                    "Domain",
                                    threat_intel_result.get(
                                        "domain",
                                        "N/A",
                                    ),
                                ],
                                [
                                    "Usage Type",
                                    threat_intel_result.get(
                                        "usage_type",
                                        "N/A",
                                    ),
                                ],
                                [
                                    "Last Reported",
                                    threat_intel_result.get(
                                        "last_reported_at",
                                        "N/A",
                                    ),
                                ],
                            ],
                            columns=[
                                "Field",
                                "Value",
                            ],
                        )

                        st.dataframe(
                            intel_table,
                            width="stretch",
                            hide_index=True,
                        )

                        st.caption(
                            "Source: AbuseIPDB. External reputation "
                            "data is provided as additional investigation "
                            "context and does not independently establish "
                            "malicious activity."
                        )

                    else:

                        st.error(
                            threat_intel_result.get(
                                "error",
                                "Threat intelligence lookup failed.",
                            )
                        )

            else:

                st.info(
                    "No IP addresses are available for enrichment."
                )

        # ====================================================
        # ANALYST ASSESSMENT
        # ====================================================

        st.write("")

        st.subheader(
            "👤 Analyst Assessment"
        )
        st.caption(
            "After reviewing SignalScope's detected evidence and AI analysis, "
            "record your current assessment of the investigation. "
            "Your saved status and notes will be included in the final "
            "exported investigation report."
        )

        with st.container(
            border=True
        ):

            assessment_col1, assessment_col2 = st.columns(
                [1, 2]
            )

            with assessment_col1:

                analyst_status = st.selectbox(
                    "Investigation Status",
                    [
                        "Investigating",
                        "Likely Benign",
                        "Escalated for Review",
                        "Confirmed Incident",
                    ],
                    index=[
                        "Investigating",
                        "Likely Benign",
                        "Escalated for Review",
                        "Confirmed Incident",
                    ].index(
                        st.session_state.analyst_status
                    ),
                    key="analyst_status_select",
                )

            with assessment_col2:

                analyst_notes = st.text_area(
                    "Analyst Notes",
                    value=st.session_state.analyst_notes,
                    placeholder=(
                        "Add investigation notes, "
                        "validation steps, or follow-up items..."
                    ),
                    key="analyst_notes_input",
                    height=100,
                )

            if st.button(
                "💾 Save Assessment",
                type="primary",
                width="stretch",
            ):

                st.session_state.analyst_status = (
                    analyst_status
                )

                st.session_state.analyst_notes = (
                    analyst_notes
                )

                st.success(
                    "Analyst assessment saved."
                )

            # ------------------------------------------------
            # Download report
            # ------------------------------------------------

            download_content = build_download_report(
    df,
    suspicious_df,
    summary_text,
    top_finding,
    threat_score,
    threat_level,
    st.session_state.generated_report,
    audience,
    report_style,
    include_mitre,
)

            st.write("")

            # ====================================================
            # EXPORT INVESTIGATION
            # ====================================================

            st.subheader(
                "📄 Export Investigation"
            )

            st.caption(
                "Export the complete investigation, including "
                "SignalScope findings, AI analysis, and your "
                "analyst assessment."
            )

            st.download_button(
                label="📥 Download Investigation Report",
                data=download_content,
                file_name="SignalScope_Investigation_Report.txt",
                mime="text/plain",
                width="stretch",
            )

            # ------------------------------------------------
            # Download PDF report
            # ------------------------------------------------

            pdf_content = build_pdf_report(
                suspicious_df=suspicious_df,
                summary_text=summary_text,
                top_finding=top_finding,
                threat_score=threat_score,
                threat_level=threat_level,
                generated_report=st.session_state.generated_report,
                audience=audience,
                report_style=report_style,
                include_mitre=include_mitre,
                analyst_status=st.session_state.analyst_status,
                analyst_notes=st.session_state.analyst_notes,
            )

            st.download_button(
                label="📑 Download PDF Investigation Report",
                data=pdf_content,
                file_name="SignalScope_Investigation_Report.pdf",
                mime="application/pdf",
                width="stretch",
            )

        # ====================================================
        # PROMPT DEBUGGING
        # ====================================================

        with st.expander(
            "Show AI Prompt"
        ):

            suspicious_events_text = (
                suspicious_df.to_string(
                    index=False
                )
            )

            prompt_preview = (
                build_ai_prompt(
                    summary_text,
                    suspicious_events_text,
                    audience=audience,
                    report_style=report_style,
                    include_mitre=include_mitre,
                    include_recommendations=include_recommendations,
                    include_confidence=include_confidence,
                    threat_score=threat_score,
                    threat_level=threat_level,
                )
            )

            st.code(
                prompt_preview,
                language="text",
            )

    except Exception as e:

        st.error(
            f"Could not analyze the file: {e}"
        )