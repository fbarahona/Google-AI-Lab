"""
Streamlit SOC Analyst Console
==============================
Entrypoint for the Cymbal Cyber SOC Portal.
Runs the refactored enterprise SOC console in src.demo.soc_ticketing.streamlit_soc_console.
"""
import os
import runpy

console_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "soc_ticketing",
    "streamlit_soc_console.py"
)

if os.path.exists(console_path):
    runpy.run_path(console_path, run_name="__main__")
else:
    import streamlit as st
    st.error(f"Could not locate SOC console script at: {console_path}")
