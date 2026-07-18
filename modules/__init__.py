"""
Backend logic for the Phishing Threat Detector.

This package is intentionally UI-agnostic: nothing in here imports Streamlit,
Flask, or any web framework. Each module takes plain Python values in and
returns plain Python values (dataclasses / dicts / lists) out. That means the
same pipeline (parse -> extract URLs -> detect keywords -> score -> explain)
can be wired up behind Streamlit (as app.py does), a Flask route, a CLI, or
a test suite without any changes to this package.
"""
