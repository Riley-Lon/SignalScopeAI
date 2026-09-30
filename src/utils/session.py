import streamlit as st


def initialize_session_state():
    """Initialize SignalScope session state variables."""

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    if "current_file_id" not in st.session_state:
        st.session_state.current_file_id = None

    if "generated_report" not in st.session_state:
        st.session_state.generated_report = None

    if "pending_question" not in st.session_state:
        st.session_state.pending_question = ""

    if "analyst_status" not in st.session_state:
        st.session_state.analyst_status = "Investigating"

    if "analyst_notes" not in st.session_state:
        st.session_state.analyst_notes = ""