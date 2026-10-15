"""
Splits the agent's markdown incident report into titled sections so the SOC
console can show the analysis, the recommendations and the raw evidence in
separate panels instead of one long blob.

The agent's reports are free-form markdown, so section detection is lenient:
markdown headings (``## Title``) and bold label lines (``**2. Behavioral
Findings:** text``) both open a new section.
"""

import re
from dataclasses import dataclass

# Heading the agent runtime appends to every ticket report with the raw output
# of each investigation sub-agent (see adk_agent.agent.append_investigation_evidence).
EVIDENCE_APPENDIX_HEADING = "## Investigation Evidence"

_MD_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
_BOLD_LABEL = re.compile(
    r"^\s{0,3}\*\*\s*(?:\d+[.)]\s*)?(?P<title>[^*\n]+?)\s*:?\s*\*\*\s*:?\s*(?P<rest>.*)$"
)
_RECOMMENDATION = re.compile(
    r"recommend|remediat|response action|next step|mitigat|containment|action plan",
    re.IGNORECASE,
)


# Markdown that makes the analyst's browser fetch or open an attacker-chosen URL.
# Report text can quote OCR from a user's desktop, so a screenshot reading
# "![](https://attacker/x)" would otherwise become a beacon when the ticket opens.
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\s*(\([^)]*\)|\[[^\]]*\])")
_MD_INLINE_LINK = re.compile(
    r"(?<!!)\[([^\]]+)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)"
)
_MD_LINK_DEFINITION = re.compile(r"(?m)^\s{0,3}\[([^\]]+)\]:\s*(\S+).*$")
_MD_AUTOLINK = re.compile(r"<((?:https?|ftp)://[^>\s]+)>")


def neutralize_markdown(text: str) -> str:
    """
    Renders untrusted report text inert: images become a "[image removed]" note and
    links show their destination as code instead of being clickable, so nothing in
    a ticket loads or opens a URL by itself.
    """
    text = _MD_IMAGE.sub(
        lambda m: f"[image removed: {m.group(1) or 'no alt text'}]", text or ""
    )
    text = _MD_INLINE_LINK.sub(lambda m: f"{m.group(1)} (`{m.group(2)}`)", text)
    text = _MD_LINK_DEFINITION.sub(lambda m: f"[{m.group(1)}]: `{m.group(2)}`", text)
    return _MD_AUTOLINK.sub(lambda m: f"`{m.group(1)}`", text)


@dataclass
class ReportSection:
    title: str
    body: str

    @property
    def is_recommendation(self) -> bool:
        return bool(_RECOMMENDATION.search(self.title))


def _clean_title(title: str) -> str:
    title = re.sub(r"^\d+[.)]\s*", "", title.strip())
    return title.strip(" :*_`")


def split_sections(
    markdown: str, default_title: str = "Summary"
) -> list[ReportSection]:
    """Returns the report as an ordered list of non-empty titled sections."""
    sections: list[ReportSection] = []
    title = default_title
    lines: list[str] = []

    def flush():
        body = "\n".join(lines).strip()
        if body:
            sections.append(ReportSection(title=title, body=body))

    for line in (markdown or "").splitlines():
        heading = _MD_HEADING.match(line)
        bold = None if heading else _BOLD_LABEL.match(line)
        if heading:
            flush()
            title, lines = _clean_title(heading.group("title")), []
        elif bold:
            flush()
            title = _clean_title(bold.group("title"))
            rest = bold.group("rest").strip()
            lines = [rest] if rest else []
        else:
            lines.append(line)
    flush()
    return sections


@dataclass
class ParsedReport:
    analysis: list[ReportSection]
    recommendations: list[ReportSection]
    evidence: list[ReportSection]


def parse_report(markdown: str) -> ParsedReport:
    """Separates the agent's analysis, its recommendations and the appended raw evidence."""
    main, _, appendix = (markdown or "").partition(EVIDENCE_APPENDIX_HEADING)
    # Drop the remainder of the appendix heading line, e.g. " (captured ...)".
    appendix = appendix.split("\n", 1)[1] if "\n" in appendix else ""
    main = re.sub(r"\n\s*---\s*$", "", main.rstrip())

    sections = split_sections(main)
    return ParsedReport(
        analysis=[s for s in sections if not s.is_recommendation],
        recommendations=[s for s in sections if s.is_recommendation],
        evidence=_split_evidence(appendix),
    )


def _split_evidence(appendix: str) -> list[ReportSection]:
    """Splits the appendix on its level-3 headings only; sub-agent text keeps its own structure."""
    sections: list[ReportSection] = []
    for chunk in re.split(r"(?m)^### ", appendix):
        title, _, body = chunk.partition("\n")
        if body.strip():
            sections.append(ReportSection(title=title.strip(), body=body.strip()))
        elif title.strip():
            sections.append(
                ReportSection(title="Additional Evidence", body=title.strip())
            )
    return sections
