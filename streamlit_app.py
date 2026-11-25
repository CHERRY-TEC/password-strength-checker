"""Streamlit demo interface for the Password Strength Checker.

Run from the project root:

    streamlit run streamlit_app.py

The demo reuses the exact same analysis engine, storage backends, summary and
export helpers as the terminal and web UI.  Like the rest of the project, it
never stores the password itself - only the derived analysis result.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import streamlit as st

# Project root on sys.path so `from psc...` works when run from anywhere.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from psc.analyzer import analyze_password, explain_rules
from psc.config import (
    EXPORT_DIR,
    JSON_PATH,
    MAX_LABEL_LENGTH,
    MAX_PASSWORD_LENGTH,
    WEAK_SCORE_THRESHOLD,
)
from psc.exporter import export_csv, export_markdown, export_text_audit
from psc.models import PasswordRecord
from psc.novelty import compare as compare_drift
from psc.seed_data import generate_records
from psc.storage import JSONStore
from psc.summary import build_alerts, build_summary, rating_distribution

st.set_page_config(
    page_title="Password Strength Checker",
    page_icon="🔐",
    layout="wide",
)

# Rating colours shared with the console UI (psc/ui.py).
RATING_COLORS = {
    "Very Strong": "#2e7d32",
    "Strong": "#66bb6a",
    "Fair": "#f9a825",
    "Weak": "#ef6c00",
    "Very Weak": "#c62828",
}


# --------------------------------------------------------------------------- #
# State helpers
# --------------------------------------------------------------------------- #
def get_store() -> JSONStore:
    return JSONStore(JSON_PATH)


@st.cache_resource(show_spinner=False)
def _store() -> JSONStore:
    return get_store()


def load_records():
    records, warnings = _store().load()
    return records, warnings


def save_records(records) -> None:
    _store().save(records)
    st.cache_resource.clear()


def next_id(records) -> int:
    return max((r.id for r in records), default=0) + 1


def color_for(rating: str) -> str:
    return RATING_COLORS.get(rating, "#555555")


# --------------------------------------------------------------------------- #
# Sidebar navigation
# --------------------------------------------------------------------------- #
st.sidebar.title("🔐 Password Strength Checker")
st.sidebar.caption("Local, private analysis — passwords are never stored.")
page = st.sidebar.radio(
    "Go to",
    ["Analyze", "Records", "Analytics", "Rules", "About"],
)
st.sidebar.divider()
records, warnings = load_records()
st.sidebar.metric("Saved records", len(records))
if warnings:
    with st.sidebar.expander("Storage warnings"):
        for w in warnings:
            st.caption(w)
st.sidebar.caption("Repo: github.com/CHERRY-TEC/password-strength-checker")


# --------------------------------------------------------------------------- #
# Analyze page
# --------------------------------------------------------------------------- #
if page == "Analyze":
    st.header("Check a password")
    st.info(
        "Analysis happens locally in memory. Only the derived score, rating and "
        "issues are saved — never the password itself."
    )

    with st.form("analyze_form", clear_on_submit=False):
        label = st.text_input(
            "Label (optional, needed only when saving)",
            max_chars=MAX_LABEL_LENGTH,
            placeholder="e.g. Banking portal",
        )
        password = st.text_input(
            "Password", type="password", max_chars=MAX_PASSWORD_LENGTH,
            placeholder="Type a password to analyse",
        )
        persist = st.checkbox("Save this analysis to history", value=False)
        submitted = st.form_submit_button("Analyze", type="primary")

    if submitted:
        if not password:
            st.error("Please enter a password.")
        else:
            result = analyze_password(password)
            del password  # plaintext discarded immediately

            st.subheader("Result")
            c1, c2, c3 = st.columns([2, 1, 1])
            with c1:
                st.markdown(
                    f"### <span style='color:{color_for(result.rating)}'>"
                    f"{result.rating}</span>", unsafe_allow_html=True
                )
                st.progress(result.score / 100)
            with c2:
                st.metric("Score", f"{result.score} / 100")
            with c3:
                st.metric("Entropy", f"{result.entropy_bits} bits")

            st.write(
                f"**Length:** {result.length} &nbsp;|&nbsp; "
                f"**Character classes:** {result.char_classes}/4 &nbsp;|&nbsp; "
                f"**Estimated crack time:** {result.crack_time}"
            )
            st.caption(
                "Classes: "
                + ", ".join(
                    name for name, present in (
                        ("uppercase", result.has_upper),
                        ("lowercase", result.has_lower),
                        ("digits", result.has_digit),
                        ("symbols", result.has_special),
                    ) if present
                )
            )

            if result.issues:
                st.warning("**Issues found**\n" + "\n".join(f"- {i}" for i in result.issues))
            else:
                st.success("No weaknesses detected.")

            if result.suggestions:
                with st.expander("Suggestions"):
                    for s in result.suggestions:
                        st.write(f"- {s}")
            if result.patterns:
                st.caption("Detected patterns: " + ", ".join(result.patterns))

            # Drift / uniqueness compared with saved history.
            history = [(r.id, r.analysis.to_dict()) for r in records]
            if history:
                drift = compare_drift(result.to_dict(), history)
                with st.expander("Similarity to saved passwords"):
                    st.write(
                        f"Nearest record: #{drift.nearest_id} | "
                        f"similarity: {drift.similarity:.0%} | "
                        f"personal risk: {drift.personal_risk}"
                    )
                    st.caption(drift.advice)

            if persist:
                clean = " ".join((label or "").split())[:MAX_LABEL_LENGTH] or "Untitled"
                if not label.strip():
                    st.warning("No label entered — saved as 'Untitled'.")
                record = PasswordRecord(
                    id=next_id(records),
                    label=clean,
                    checked_at=datetime.now().isoformat(timespec="seconds"),
                    analysis=result,
                )
                updated = list(records) + [record]
                save_records(updated)
                st.success(f"Saved as record #{record.id} ('{clean}').")
                if result.score < WEAK_SCORE_THRESHOLD:
                    st.caption("⚠️ This password is weak — consider changing it.")


# --------------------------------------------------------------------------- #
# Records page
# --------------------------------------------------------------------------- #
elif page == "Records":
    st.header("Saved records")
    st.caption("Only analysis metadata is stored — no passwords.")

    col1, col2, col3 = st.columns(3)
    keyword = col1.text_input("Search keyword", "")
    rating_filter = col2.selectbox(
        "Rating", ["All"] + list(RATING_COLORS.keys())
    )
    min_score = col3.slider("Minimum score", 0, 100, 0)

    filtered = [
        r for r in records
        if r.matches(keyword.split())
        and (rating_filter == "All" or r.rating == rating_filter)
        and r.score >= min_score
    ]
    st.caption(f"Showing {len(filtered)} of {len(records)} records")

    if filtered:
        data = [
            {
                "ID": r.id,
                "Label": r.label,
                "Checked at": r.checked_at,
                "Score": r.score,
                "Rating": r.rating,
                "Length": r.analysis.length,
                "Entropy (bits)": r.analysis.entropy_bits,
                "Issues": ", ".join(r.analysis.issues) or "—",
            }
            for r in filtered
        ]
        st.dataframe(data, use_container_width=True, hide_index=True)

        with st.expander("Details"):
            sel = st.selectbox(
                "Record", options=[r.id for r in filtered],
                format_func=lambda i: f"#{i} — {next(r.label for r in filtered if r.id == i)}",
            )
            r = next(r for r in filtered if r.id == sel)
            st.write(f"**Rating:** {r.rating} | **Score:** {r.score}/100")
            st.write(f"**Crack time:** {r.analysis.crack_time}")
            st.write("**Issues:** " + (", ".join(r.analysis.issues) or "none"))
            st.write("**Suggestions:** " + (", ".join(r.analysis.suggestions) or "none"))
    else:
        st.info("No records match the filters.")

    st.divider()
    a, b = st.columns(2)
    with a:
        count = st.number_input("Generate sample records", 1, 200, 40)
        if st.button("Seed sample data"):
            existing = list(records)
            generated = generate_records(int(count), start_id=next_id(existing))
            save_records(existing + generated)
            st.success(f"Added {len(generated)} sample records. Refresh to view.")
    with b:
        if st.button("Clear all records"):
            save_records([])
            st.warning("All records cleared.")


# --------------------------------------------------------------------------- #
# Analytics page
# --------------------------------------------------------------------------- #
elif page == "Analytics":
    st.header("Executive summary")
    if not records:
        st.info("No records yet. Use the Analyze or Records page to add some.")
    else:
        report = build_summary(records)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total records", report.total)
        c2.metric("Average score", f"{report.average_score:.1f}")
        c3.metric("Median score", f"{report.median_score:.1f}")
        c4.metric("Average length", f"{report.average_length:.1f}")
        c5, c6, c7, c8 = st.columns(4)
        c5.metric("Weak share", f"{report.weak_rate:.0%}")
        c6.metric("Strong share", f"{report.strong_rate:.0%}")
        c7.metric("Min score", report.min_score)
        c8.metric("Max score", report.max_score)

        st.subheader("Rating distribution")
        dist = rating_distribution(report)
        st.bar_chart({rating: count for rating, count in reversed(dist)})

        st.subheader("Common issues")
        st.bar_chart(dict(report.common_issues))

        st.subheader("Alerts")
        for level, message in build_alerts(report):
            if level == "critical":
                st.error(message)
            elif level == "warning":
                st.warning(message)
            else:
                st.info(message)

        st.subheader("Exports")
        EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        ec1, ec2, ec3 = st.columns(3)
        with ec1:
            if st.button("Export Markdown report"):
                p = export_markdown(
                    records, report, EXPORT_DIR / f"summary-{stamp}.md"
                )
                st.success(f"Saved: {p.name}")
        with ec2:
            if st.button("Export CSV"):
                p = export_csv(records, EXPORT_DIR / f"records-{stamp}.csv")
                st.success(f"Saved: {p.name}")
        with ec3:
            if st.button("Export text audit"):
                p = export_text_audit(
                    records, report, EXPORT_DIR / f"audit-{stamp}.txt"
                )
                st.success(f"Saved: {p.name}")


# --------------------------------------------------------------------------- #
# Rules page
# --------------------------------------------------------------------------- #
elif page == "Rules":
    st.header("Password strength rules")
    st.caption("The same rules returned by the engine's explain_rules() API.")
    for rule in explain_rules():
        with st.expander(rule["title"]):
            st.write(f"**Rule:** {rule['rule']}")
            st.caption(rule["why"])


# --------------------------------------------------------------------------- #
# About page
# --------------------------------------------------------------------------- #
else:
    st.header("About this demo")
    st.markdown(
        """
        This Streamlit interface is an easy-demo front end for the
        **Password Strength Checker** mini project. It reuses the same core
        modules as the terminal application and the browser UI:

        - `psc.analyzer` — local entropy, pattern and heuristic analysis
        - `psc.storage` / `psc.sqlite_store` — interchangeable storage backends
        - `psc.summary` and `psc.novelty` — analytics and structural drift
        - `psc.exporter` — Markdown, CSV, text and PNG exports

        **Privacy:** the password is analysed in memory and discarded
        immediately. Only derived metadata (score, rating, length, issues)
        is ever saved.

        - Repo: https://github.com/CHERRY-TEC/password-strength-checker
        - Live browser version: https://password-strength-checker-theta-puce.vercel.app
        - Tests: 92 Python + 13 JavaScript automated tests pass
        """
    )
