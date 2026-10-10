"""Turn a privacy policy into sentence-sized chunks that know their heading (D-037).

Markdown is the common format: GitHub policies arrive as markdown, and HTML pages are
converted to markdown by the extractor (headings as ``#``, tables as pipe tables). This
module parses that markdown into blocks and the blocks into chunks:

- every chunk carries ``section_path``, the headings above it (``["Permissions",
  "CAMERA"]``), and ``section``, the nearest one. The page title is kept apart;
- the lines of a paragraph are joined before it is split into sentences, and a sentence
  only ends at ``.``, ``!`` or ``?`` followed by a space and a capital letter or digit, so
  a dotted name such as ``WifiManager.getConfiguredNetworks`` stays whole;
- a table gives one chunk per row, written ``Header1: cell; Header2: cell``.

Everything here is plain-text processing of untrusted input. Nothing is rendered or run.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

from .models import PolicyChunk

MAX_CHUNKS = 400
MAX_CHUNK_CHARS = 600
MAX_ROW_CHARS = 1000
MAX_SECTION_CHARS = 120
MAX_SECTION_DEPTH = 6
# A short paragraph that is only bold text is treated as a heading (HTML pages often
# style headings with <strong> instead of <h2>).
MAX_BOLD_HEADING_WORDS = 8
# Deeper than any real heading (h1-h6), so a bold heading nests under the last real one.
_BOLD_HEADING_LEVEL = 7

_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_ATX_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_SETEXT_UNDERLINE = re.compile(r"^\s{0,3}(=+|-+)\s*$")
_RULE = re.compile(r"^\s{0,3}([-*_])(\s*\1){2,}\s*$")
_REFERENCE_DEFINITION = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*\S+.*$")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d{1,3}[.)])\s+(.*)$")
_TABLE_DELIMITER = re.compile(r"^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$")
_ESCAPED = re.compile(r"\\([\\`*_{}\[\]()#+\-.!|>~])")
_BOLD_ONLY = re.compile(r"^(?:\*\*([^*]+)\*\*|__([^_]+)__)\s*:?$")

# A sentence can end here: ., ! or ? (plus a closing quote or bracket), whitespace, then
# something that starts a sentence. A dot inside a name has no space after it.
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])[\"'\u201d\u2019)\]]?\s+(?=[\"'\u201c\u2018(\[]?[A-Z0-9])")
# Words that end in a dot without ending the sentence.
_ABBREVIATIONS = frozenset(
    {"e.g.", "i.e.", "eg.", "ie.", "vs.", "cf.", "no.", "inc.", "ltd.", "co.", "corp.", "llc.",
     "mr.", "mrs.", "ms.", "dr.", "st.", "art.", "sec.", "para.", "u.s.", "u.k.", "e.u."}
)  # fmt: skip


@dataclass(frozen=True)
class Heading:
    level: int
    text: str


@dataclass(frozen=True)
class Paragraph:
    text: str


@dataclass(frozen=True)
class TableRow:
    headers: tuple[str, ...]
    cells: tuple[str, ...]


Block = Heading | Paragraph | TableRow


@dataclass
class ChunkedPolicy:
    chunks: list[PolicyChunk] = field(default_factory=list)
    title: str | None = None
    truncated: bool = False


# --------------------------------------------------------------------------- inline text


def plain_text(markdown: str) -> str:
    """Inline markdown as plain text.

    A link keeps its **text**, never its target or its reference label:
    ``[ACCESS_WIFI_STATE][ACCESS_FINE_LOCATION]`` is "ACCESS_WIFI_STATE".
    """
    # Park backslash-escaped characters first, so "\\*" is not read as emphasis.
    text = _ESCAPED.sub(
        lambda match: f"\x00{ord(match.group(1))}\x00", markdown.replace("\x00", "")
    )
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", text)  # image
    text = re.sub(r"!\[([^\]]*)\]\[[^\]]*\]", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)  # [text](url)
    text = re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", text)  # [text][label]
    text = re.sub(r"\[([^\]]+)\](?![(\[:])", r"\1", text)  # [text]
    text = re.sub(r"<((?:https?://|mailto:)[^>\s]+)>", r"\1", text)  # <autolink>
    text = re.sub(r"</?[A-Za-z][^>]*>", " ", text)  # raw HTML tags
    text = re.sub(r"(`+)(.+?)\1", r"\2", text)  # `code`
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"(?<![A-Za-z0-9_])__(.+?)__(?![A-Za-z0-9_])", r"\1", text)
    text = re.sub(r"(?<![*\w])\*([^*\n]+)\*(?!\w)", r"\1", text)
    # Underscore emphasis only at word edges, so ACCESS_FINE_LOCATION is left alone.
    text = re.sub(r"(?<![A-Za-z0-9_])_([^_\n]+)_(?![A-Za-z0-9_])", r"\1", text)
    text = re.sub(r"~~(.+?)~~", r"\1", text)
    text = re.sub(r"\x00(\d+)\x00", lambda match: chr(int(match.group(1))), text)
    text = html.unescape(text)
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\t\n")
    return " ".join(text.split())


# --------------------------------------------------------------------------- blocks


def _cells(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|") and not stripped.endswith("\\|"):
        stripped = stripped[:-1]
    return [plain_text(cell.replace("\\|", "|")) for cell in re.split(r"(?<!\\)\|", stripped)]


def _is_table_start(lines: list[str], index: int) -> bool:
    return (
        "|" in lines[index]
        and index + 1 < len(lines)
        and "|" in lines[index + 1]
        and bool(_TABLE_DELIMITER.match(lines[index + 1]))
    )


def parse_blocks(markdown: str, *, bold_headings: bool = False) -> list[Block]:
    """Split markdown into headings, paragraphs (list items included) and table rows.

    ``bold_headings`` turns a short paragraph that is only bold text into a heading.
    """
    lines = markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    blocks: list[Block] = []
    buffer: list[str] = []

    def flush() -> None:
        if not buffer:
            return
        raw = " ".join(line.strip() for line in buffer).strip()
        buffer.clear()
        bold = _BOLD_ONLY.match(raw) if bold_headings else None
        if bold and len((bold.group(1) or bold.group(2)).split()) <= MAX_BOLD_HEADING_WORDS:
            text = plain_text(bold.group(1) or bold.group(2))
            if text:
                blocks.append(Heading(_BOLD_HEADING_LEVEL, text))
            return
        text = plain_text(raw)
        if text:
            blocks.append(Paragraph(text))

    index = 0
    while index < len(lines):
        line = lines[index]
        fence = _FENCE.match(line)
        if fence:
            # Code blocks are not policy statements: skip to the closing fence.
            flush()
            marker = fence.group(1)[0] * 3
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith(marker):
                index += 1
            index += 1
            continue
        if not line.strip() or _REFERENCE_DEFINITION.match(line):
            # A blank line ends the paragraph; a link-reference definition is not text.
            flush()
        elif heading := _ATX_HEADING.match(line):
            flush()
            text = plain_text(heading.group(2))
            if text:
                blocks.append(Heading(len(heading.group(1)), text))
        elif _is_table_start(lines, index):
            flush()
            headers = tuple(_cells(line))
            index += 2
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                blocks.append(TableRow(headers, tuple(_cells(lines[index]))))
                index += 1
            continue
        elif buffer and (underline := _SETEXT_UNDERLINE.match(line)):
            level = 1 if underline.group(1).startswith("=") else 2
            text = plain_text(" ".join(part.strip() for part in buffer))
            buffer.clear()
            if text:
                blocks.append(Heading(level, text))
        elif _RULE.match(line):
            flush()
        elif item := _LIST_ITEM.match(line):
            flush()
            buffer.append(item.group(1))
        else:
            buffer.append(re.sub(r"^\s{0,3}>\s?", "", line))  # blockquote marker
        index += 1
    flush()
    return blocks


# --------------------------------------------------------------------------- sentences


def _ends_with_abbreviation(piece: str) -> bool:
    """True if the dot that ends ``piece`` does not end a sentence."""
    # A list number on its own ("2." before "Sharing").
    if re.fullmatch(r"\(?\d{1,3}[.)]", piece):
        return True
    return piece.rsplit(None, 1)[-1].lower().lstrip("(\"'") in _ABBREVIATIONS


def _split_long(piece: str) -> list[str]:
    parts = []
    while len(piece) > MAX_CHUNK_CHARS:
        cut = piece.rfind(" ", 0, MAX_CHUNK_CHARS)
        cut = cut if cut > 0 else MAX_CHUNK_CHARS
        parts.append(piece[:cut])
        piece = piece[cut:].lstrip()
    if piece:
        parts.append(piece)
    return parts


def split_sentences(paragraph: str) -> list[str]:
    """Split one paragraph into sentences, at real sentence ends only."""
    sentences: list[str] = []
    carry = ""
    for piece in _SENTENCE_BREAK.split(paragraph):
        candidate = f"{carry} {piece}".strip() if carry else piece.strip()
        if not candidate:
            continue
        if _ends_with_abbreviation(candidate):
            carry = candidate
            continue
        carry = ""
        # A one-word fragment is never a sentence of its own: it joins the one before.
        if sentences and len(candidate.split()) < 2:
            sentences[-1] = f"{sentences[-1]} {candidate}"
        else:
            sentences.append(candidate)
    if carry:
        if sentences and len(carry.split()) < 2:
            sentences[-1] = f"{sentences[-1]} {carry}"
        else:
            sentences.append(carry)
    return [part for sentence in sentences for part in _split_long(sentence)]


def _row_text(row: TableRow) -> str:
    parts = []
    for position, cell in enumerate(row.cells):
        if not cell:
            continue
        header = row.headers[position] if position < len(row.headers) else ""
        parts.append(f"{header}: {cell}" if header else cell)
    text = "; ".join(parts)
    return text if len(text) <= MAX_ROW_CHARS else text[: MAX_ROW_CHARS - 1] + "…"


# --------------------------------------------------------------------------- chunks


def _clip_section(text: str) -> str:
    return text if len(text) <= MAX_SECTION_CHARS else text[: MAX_SECTION_CHARS - 1] + "…"


def _page_title(blocks: list[Block]) -> Heading | None:
    """The document's title: its first heading, if that is the only level-1 heading.

    A page that uses several level-1 headings uses them as sections, not as a title.
    """
    headings = [block for block in blocks if isinstance(block, Heading)]
    level_one = [heading for heading in headings if heading.level == 1]
    if len(level_one) == 1 and headings[0] is level_one[0]:
        return level_one[0]
    return None


def chunk_markdown(markdown: str, *, bold_headings: bool = False) -> ChunkedPolicy:
    """Chunk a policy written in (or converted to) markdown.

    Ids are ``pol_001``, ``pol_002``, … in reading order and depend only on the text, so
    the same policy always gives the same ids. A chunk is dropped as a duplicate only if
    its section path **and** its text both match an earlier chunk: the same sentence
    under "Data we collect > Location" and "Data we share > Location" is kept twice.
    """
    blocks = parse_blocks(markdown, bold_headings=bold_headings)
    title = _page_title(blocks)

    pieces: list[tuple[tuple[str, ...], str]] = []
    seen: set[tuple[tuple[str, ...], str]] = set()
    stack: list[Heading] = []

    for block in blocks:
        if isinstance(block, Heading):
            if block is title:
                continue
            while stack and stack[-1].level >= block.level:
                stack.pop()
            stack.append(block)
            continue
        path = tuple(_clip_section(heading.text) for heading in stack[-MAX_SECTION_DEPTH:])
        texts = [_row_text(block)] if isinstance(block, TableRow) else split_sentences(block.text)
        for text in texts:
            key = (path, text)
            if text and key not in seen:
                seen.add(key)
                pieces.append(key)

    chunks = [
        PolicyChunk(
            id=f"pol_{number:03d}",
            section=path[-1] if path else None,
            section_path=list(path),
            text=text,
        )
        for number, (path, text) in enumerate(pieces[:MAX_CHUNKS], start=1)
    ]
    return ChunkedPolicy(
        chunks=chunks,
        title=_clip_section(title.text) if title else None,
        truncated=len(pieces) > MAX_CHUNKS,
    )
