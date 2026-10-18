"""
Building blocks of the SOC console (streamlit_soc_console.py is the entry script).

Streamlit re-runs the entry script on every interaction but imports these modules
once, so they hold only functions and constants; every module-level Streamlit call
(page config, theme, session defaults, sidebar, navigation) stays in the entry
script. The folder is not named `pages/`, which Streamlit would treat as its own
multipage app.

- config: environment settings and display constants
- theme: the console CSS
- data: the cached ticketing service and reads, demo actions
- formatting: labels and ticket helpers
- ticket_detail: the ticket dossier and the Ask the Agent chat
- overview, triage, archive: the three pages
- navigation: the page registry and the sidebar panels
"""
