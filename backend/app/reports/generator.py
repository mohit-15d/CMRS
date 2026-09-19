"""Stage 19 - PDF chain-of-custody report generator (ReportLab).

Produces the reference "EVIDENCE CHAIN OF CUSTODY TRACKING FORM" layout:
A4 portrait, bordered section tables, in the reference section order:

  1. Header
  2. Case information (Case Number / Offense / Submitting Officer / Victim /
     Suspect / Date-Time Seized / Location of Seizure)
  3. DESCRIPTION OF EVIDENCE  (Item # / Quantity / Description of Item,
     including Model, Serial #, Condition, Marks, Scratches, Evidence ID)
  4. CMRS digital evidence information (Evidence ID / SHA-256 / Integrity
     Status / Encryption Status) integrated without breaking the form layout
  5. CHAIN OF CUSTODY (Item # / Date-Time / Released By (Signature & ID#) /
     Received By (Signature & ID#) / Comments-Location)
  6. FINAL DISPOSAL AUTHORITY
  7. FORENSIC ACKNOWLEDGMENT

Every rendered value comes from the data dict built by
``collect_case_report_data`` from actual database records. Optional fields
that are unavailable render as "" (blank line) or "Not Provided" - forensic
information is never invented.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _xml_escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.custody_transfer import CustodyTransfer
from app.security.audit_ledger import verify_audit_chain

#: All CMRS evidence is encrypted at rest with AES-256-GCM (Stage 12).
ENCRYPTION_STATUS_LABEL = "AES-256-GCM ENCRYPTED (AT REST)"


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _fmt_dt(dt: datetime | None) -> str:
    """Format a datetime for the form; missing values stay blank/Not Provided."""
    utc = _utc(dt)
    if utc is None:
        return "Not Provided"
    return utc.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


def _na(value: object) -> str:
    """Render a value or the neutral 'Not Provided' placeholder."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return "Not Provided"
    return str(value)


def _esc(value: object) -> str:
    """XML-escape a dynamic value for safe use inside Paragraph markup."""
    if value is None:
        return ""
    return _xml_escape(str(value))


def collect_case_report_data(
    db: Session,
    case: Case,
    report_identifier: str,
    generated_at: datetime | None = None,
) -> dict:
    """Collect ALL report values from actual database records.

    No value is hard-coded or invented: case fields, evidence, original
    SHA-256 hashes, verification results, custody history (with custodian
    usernames) and the live audit-chain verification result are read from
    the database. Unavailable optional fields become ``None`` and render
    as blank / "Not Provided" in the PDF.
    """
    from app.models.user import User

    generated_at = generated_at or datetime.now(timezone.utc)

    user_cache: dict = {}

    def username(user_id):
        if user_id is None:
            return None
        if user_id not in user_cache:
            user = db.get(User, user_id)
            user_cache[user_id] = user.username if user else None
        return user_cache[user_id]

    evidence_rows = sorted(
        case.evidence,
        key=lambda e: (e.item_number is None, e.item_number or 0, e.created_at),
    )

    items: list[dict] = []
    for ev in evidence_rows:
        original = next((h for h in ev.hashes if h.hash_type == "original"), None)
        verifications = sorted(
            (h for h in ev.hashes if h.hash_type == "verification" and h.verified_at),
            key=lambda h: h.verified_at,
        )
        latest = verifications[-1] if verifications else None
        if latest is None or latest.match_result is None:
            integrity_status = "NOT VERIFIED"
        elif latest.match_result is True:
            integrity_status = "VERIFIED"
        else:
            integrity_status = "MISMATCH"

        events = db.scalars(
            select(CustodyTransfer)
            .where(CustodyTransfer.evidence_id == ev.id)
            .order_by(CustodyTransfer.transferred_at, CustodyTransfer.id)
        ).all()
        custody = [
            {
                "transferred_at": t.transferred_at,
                "released_by": username(t.previous_custodian_id),
                "received_by": username(t.new_custodian_id),
                "action": t.action,
                "comments": t.reason,
                "location": t.location,
            }
            for t in events
        ]

        items.append(
            {
                "item_number": ev.item_number,
                "evidence_id": str(ev.id),
                "description": ev.description,
                "original_filename": ev.original_filename,
                "sha256": original.sha256_hex if original else None,
                "integrity_status": integrity_status,
                "last_verified_at": latest.verified_at if latest else None,
                "encryption_status": ENCRYPTION_STATUS_LABEL,
                "custody": custody,
            }
        )

    chain_valid, _detail = verify_audit_chain(db)

    return {
        "report_identifier": report_identifier,
        "generated_at": generated_at,
        "audit_verification_status": "AUDIT CHAIN VALID" if chain_valid else "AUDIT CHAIN INVALID",
        "case": {
            "case_number": case.case_number,
            "title": case.title,
            "status": case.status,
            "offense": case.offense,
            "victim": case.victim,
            "suspect": case.suspect,
            "submitting_officer": case.submitting_officer,
            "location": case.location,
            "seized_at": case.seized_at,
        },
        "items": items,
    }


# --- RENDER: reference-form layout ---------------------------------------

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

_BLACK = colors.black
_GREY = colors.HexColor("#DDDDDD")

_ST_TITLE = ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=14, leading=17, alignment=TA_CENTER)
_ST_SUB = ParagraphStyle("sub", fontName="Helvetica", fontSize=8, leading=10, alignment=TA_CENTER)
_ST_SECTION = ParagraphStyle("section", fontName="Helvetica-Bold", fontSize=11, leading=13, spaceBefore=12, spaceAfter=4)
_ST_CELL = ParagraphStyle("cell", fontName="Helvetica", fontSize=8.5, leading=10.5)
_ST_SMALL = ParagraphStyle("small", fontName="Helvetica", fontSize=7.5, leading=9)
_ST_SHA = ParagraphStyle("sha", fontName="Courier", fontSize=6.8, leading=8.4)
_ST_CERT = ParagraphStyle("cert", fontName="Helvetica", fontSize=8.5, leading=11)
# Layout-fix styles (format-preserving): labels become wrapping Paragraphs so
# they can never draw over a neighbouring cell; technical timestamps get a
# slightly smaller font so a full date+time fits its column on one line.
_ST_LABEL = ParagraphStyle("label", fontName="Helvetica", fontSize=8.5, leading=10.5)
_ST_DT = ParagraphStyle("dt", fontName="Helvetica", fontSize=7, leading=8.4)
_ST_HDR = ParagraphStyle("hdr", fontName="Helvetica", fontSize=10, leading=12)

_PAGE_W, _PAGE_H = A4
_MARGIN = 15 * mm
_USABLE = _PAGE_W - 2 * _MARGIN  # 180 mm


def _grid(header_rows: int = 1) -> TableStyle:
    return TableStyle(
        [
            ("GRID", (0, 0), (-1, -1), 0.6, _BLACK),
            ("BACKGROUND", (0, 0), (-1, header_rows - 1), _GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
    )


def _p(value: object, style: ParagraphStyle = _ST_CELL) -> Paragraph:
    return Paragraph(_esc(value) if value not in (None, "") else "", style)


def _sha_cell(sha256: str | None) -> Paragraph:
    if not sha256:
        return Paragraph("Not Provided", _ST_SHA)
    return Paragraph(f"{_esc(sha256[:32])}<br/>{_esc(sha256[32:])}", _ST_SHA)


def _id_cell(evidence_id: str | None) -> Paragraph:
    """Evidence-ID (UUID) cell: deterministic 18/18 line split, like _sha_cell.

    The value itself is never altered - only the visual line break, so the
    UUID stays complete and never breaks at an arbitrary character.
    """
    if not evidence_id:
        return Paragraph("Not Provided", _ST_SHA)
    half = max(1, len(evidence_id) // 2)
    return Paragraph(f"{_esc(evidence_id[:half])}<br/>{_esc(evidence_id[half:])}", _ST_SHA)


def _lbl(text: str) -> Paragraph:
    """Form label as a wrapping Paragraph - cannot draw over a neighbouring cell."""
    return Paragraph(_esc(text), _ST_LABEL)


def _description_cell(item: dict) -> Paragraph:
    lines = [
        _esc(item["description"]) if item["description"] else "(No description provided)",
        "Model: Not Provided",
        "Serial #: Not Provided",
        "Condition: Not Provided",
        "Marks/Scratches: Not Provided",
        f"Evidence ID: {_esc(item['evidence_id'])}",
        f"File: {_esc(item['original_filename'])}",
    ]
    return Paragraph("<br/>".join(lines), _ST_CELL)


def _comments_cell(event: dict) -> Paragraph:
    parts = [event.get("action"), event.get("comments"), event.get("location")]
    joined = " | ".join(_na(p) for p in parts if p)
    return Paragraph(_esc(joined) if joined else "", _ST_CELL)


def build_report_story(data: dict) -> list:
    """Build the reference-form Platypus story from collected report data."""
    case = data["case"]
    items = data["items"]
    story: list = []

    # 1. Header -----------------------------------------------------------
    story.append(Paragraph("EVIDENCE CHAIN OF CUSTODY TRACKING FORM", _ST_TITLE))
    story.append(Spacer(1, 3))
    story.append(
        Paragraph(
            "Chain-of-Custody Management &amp; Reporting System (CMRS)"
            f" &nbsp;|&nbsp; Report ID: {_esc(data['report_identifier'])}"
            f" &nbsp;|&nbsp; Generated: {_esc(_fmt_dt(data['generated_at']))}"
            f" &nbsp;|&nbsp; Audit Verification: {_esc(data['audit_verification_status'])}",
            _ST_SUB,
        )
    )
    story.append(Spacer(1, 8))

    # 2. Case information ---------------------------------------------------
    case_rows = [
        [_lbl("Case Number:"), _p(case["case_number"]), _lbl("Offense:"), _p(case["offense"])],
        [_lbl("Submitting Officer (Name/ID#):"), _p(case["submitting_officer"]), _lbl("Victim:"), _p(case["victim"])],
        [_lbl("Suspect:"), _p(case["suspect"]), _lbl("Date/Time Seized:"), _p(_fmt_dt(case["seized_at"]))],
        [_lbl("Location of Seizure:"), _p(case["location"]), _lbl("Case Status:"), _p(case["status"])],
        [_lbl("Case Title:"), _p(case["title"]), "", ""],
    ]
    story.append(Table(case_rows, colWidths=[42 * mm, 52 * mm, 34 * mm, 52 * mm], style=_grid(0)))
    story.append(Spacer(1, 2))

    # 3. DESCRIPTION OF EVIDENCE --------------------------------------------
    story.append(Paragraph("DESCRIPTION OF EVIDENCE", _ST_SECTION))
    desc_header = ["Item #", "Quantity", "Description of Item"]
    if items:
        desc_rows = [desc_header] + [
            [_p(i["item_number"] if i["item_number"] is not None else "-"), _p("1"), _description_cell(i)]
            for i in items
        ]
    else:
        desc_rows = [desc_header, [Paragraph("No evidence items recorded for this case.", _ST_CELL), "", ""]]
    desc_table = Table(desc_rows, colWidths=[16 * mm, 18 * mm, _USABLE - 34 * mm], style=_grid(), repeatRows=1)
    if not items:
        desc_table.setStyle(TableStyle([("SPAN", (0, 1), (-1, 1))]))
    story.append(desc_table)
    story.append(Spacer(1, 2))

    # 4. CMRS digital evidence information -----------------------------------
    story.append(Paragraph("CMRS DIGITAL EVIDENCE INFORMATION (SYSTEM VERIFICATION)", _ST_SECTION))
    cmrs_header = ["Evidence ID", "SHA-256", "Integrity Status", "Encryption Status"]
    if items:
        cmrs_rows = [cmrs_header] + [
            [
                _id_cell(i["evidence_id"]),
                _sha_cell(i["sha256"]),
                _p(i["integrity_status"]),
                _p(i["encryption_status"], _ST_SMALL),
            ]
            for i in items
        ]
    else:
        cmrs_rows = [cmrs_header, [Paragraph("No evidence items recorded for this case.", _ST_CELL), "", "", ""]]
    cmrs_table = Table(cmrs_rows, colWidths=[40 * mm, 66 * mm, 32 * mm, _USABLE - 138 * mm], style=_grid(), repeatRows=1)
    if not items:
        cmrs_table.setStyle(TableStyle([("SPAN", (0, 1), (-1, 1))]))
    story.append(cmrs_table)

    # 5. CHAIN OF CUSTODY -----------------------------------------------------
    story.append(Paragraph("CHAIN OF CUSTODY", _ST_SECTION))
    custody_header = [
        _p("Item #", _ST_HDR),
        _p("Date/Time", _ST_HDR),
        _p("Released By (Signature & ID#)", _ST_HDR),
        _p("Received By (Signature & ID#)", _ST_HDR),
        _p("Comments/Location", _ST_HDR),
    ]
    custody_rows: list = [custody_header]
    has_events = False
    for i in items:
        for event in i["custody"]:
            has_events = True
            custody_rows.append(
                [
                    _p(i["item_number"] if i["item_number"] is not None else "-"),
                    _p(_fmt_dt(event["transferred_at"]), _ST_DT),
                    _p(event["released_by"]),
                    _p(event["received_by"]),
                    _comments_cell(event),
                ]
            )
    if not has_events:
        custody_rows.append([Paragraph("No custody events recorded for this case.", _ST_CELL), "", "", "", ""])
    custody_table = Table(
        custody_rows,
        colWidths=[14 * mm, 34 * mm, 36 * mm, 36 * mm, _USABLE - 120 * mm],
        style=_grid(),
        repeatRows=1,
    )
    if not has_events:
        custody_table.setStyle(TableStyle([("SPAN", (0, 1), (-1, 1))]))
    story.append(custody_table)

    # 6. FINAL DISPOSAL AUTHORITY ----------------------------------------------
    item_numbers = ", ".join(
        str(i["item_number"]) if i["item_number"] is not None else "(unnumbered)" for i in items
    ) or "Not Provided"
    disposal = Table(
        [
            ["Item(s) #:", _p(item_numbers)],
            ["Release Information:", _p("")],
            ["Evidence Custodian:", _p("")],
            ["Name:", _p("Not Provided")],
            ["ID #:", _p("Not Provided")],
            ["Address:", _p("")],
            ["City:", _p("")],
            ["State:", _p("")],
            ["Zip Code:", _p("")],
            ["Telephone Number:", _p("")],
        ],
        colWidths=[52 * mm, _USABLE - 52 * mm],
        style=_grid(0),
        rowHeights=[None, 9 * mm, 9 * mm, None, None, 9 * mm, 7 * mm, 7 * mm, 7 * mm, 9 * mm],
    )
    disposal_section = [
        Paragraph("FINAL DISPOSAL AUTHORITY", _ST_SECTION),
        disposal,
        Spacer(1, 6),
        Paragraph(
            "Certification: The undersigned certifies that the information recorded on this "
            "form is accurate to the best of their knowledge and that the evidence described "
            "above was handled in accordance with chain-of-custody procedures.",
            _ST_CERT,
        ),
        Spacer(1, 10),
        Paragraph(
            "Signature: ______________________________&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
            "Date: ____________________",
            _ST_CERT,
        ),
        Spacer(1, 6),
        Paragraph(
            "Government-issued photo identification: &nbsp;&nbsp; [&nbsp;&nbsp;] Yes "
            "&nbsp;&nbsp;&nbsp;&nbsp; [&nbsp;&nbsp;] No",
            _ST_CERT,
        ),
    ]
    story.append(KeepTogether(disposal_section))

    # 7. FORENSIC ACKNOWLEDGMENT -------------------------------------------------
    acknowledgment = Table(
        [
            ["Received By (Technician / Examiner):", _p("")],
            ["Signature:", _p("")],
            ["Date & Time of Receipt:", _p("")],
            ["Remarks:", _p("")],
        ],
        colWidths=[62 * mm, _USABLE - 62 * mm],
        style=_grid(0),
        rowHeights=[9 * mm, 12 * mm, 9 * mm, 16 * mm],
    )
    story.append(KeepTogether([Paragraph("FORENSIC ACKNOWLEDGMENT", _ST_SECTION), acknowledgment]))

    return story


def _footer(data: dict):
    def _draw(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(_BLACK)
        canvas.setLineWidth(0.5)
        canvas.line(_MARGIN, 12 * mm, _PAGE_W - _MARGIN, 12 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(_MARGIN, 8 * mm, "CMRS - Evidence Chain of Custody Tracking Form")
        canvas.drawRightString(
            _PAGE_W - _MARGIN,
            8 * mm,
            "Report ID: %s  |  Page %d" % (data["report_identifier"], canvas.getPageNumber()),
        )
        canvas.restoreState()

    return _draw


def render_pdf(data: dict) -> bytes:
    """Render the collected report data to the reference-form PDF (A4)."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=_MARGIN,
        rightMargin=_MARGIN,
        topMargin=14 * mm,
        bottomMargin=18 * mm,
        title="Evidence Chain of Custody Tracking Form",
        author="CMRS - Chain-of-Custody Management & Reporting System",
        subject=f"Report ID {data['report_identifier']}",
    )
    doc.build(build_report_story(data), onFirstPage=_footer(data), onLaterPages=_footer(data))
    return buffer.getvalue()

