"""YAML loading for actions-audit, with two interchangeable backends.

Backend 1 -- PyYAML, used when ``import yaml`` succeeds.
Backend 2 -- :func:`load_native`, a dependency-free reader for the YAML subset
that GitHub Actions workflow files actually use (block mappings, block
sequences, flow collections, quoted/plain scalars, block scalars, comments,
multi-line flow collections).

Both backends return the same shape: ``(data, lines)`` where ``data`` is plain
Python data and ``lines`` maps a dotted/indexed path to the 1-based source line
of the token that *starts* that node.

YAML 1.1 trap handled here
--------------------------
PyYAML implements YAML 1.1, where the unquoted scalar ``on`` is the boolean
true.  So in a workflow file the top-level key written ``on:`` is delivered as
the **boolean** ``True``, not the string ``"on"``.  It is also a *string* key in
the native backend, because the native reader never coerces mapping keys.  Both
are handled: :func:`get_workflow_triggers` accepts either spelling, and
:func:`top_level_key_style` tells the caller how ``on:`` was actually parsed so
the audit can record the fact in its report.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "YamlError",
    "SplitError",
    "pyyaml_available",
    "backend_name",
    "load_file",
    "load_string",
    "load_native",
    "get_workflow_triggers",
    "on_key_kind",
    "ON_KEY_STR",
    "ON_KEY_BOOL",
    "ON_KEY_NONE",
]

# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class YamlError(Exception):
    """Raised for any YAML syntax problem, by either backend."""

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        self.line = line
        if line is not None:
            message = "line %d: %s" % (line, message)
        super().__init__(message)


class SplitError(YamlError):
    """Raised when a file is not exactly one YAML document."""


try:  # pragma: no cover - exercised on both branches in the test suite
    import yaml as _pyyaml  # type: ignore
except Exception:  # pragma: no cover
    _pyyaml = None


def pyyaml_available() -> bool:
    """True when PyYAML can be imported in this interpreter."""
    return _pyyaml is not None


def backend_name(prefer_native: bool = False) -> str:
    """Name of the backend :func:`load_file` would use right now."""
    if prefer_native or _pyyaml is None:
        return "native"
    return "pyyaml"


# --------------------------------------------------------------------------
# Native reader
# --------------------------------------------------------------------------

_NULLS = {"", "~", "null", "Null", "NULL"}
_TRUE_11 = {"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"}
_FALSE_11 = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"}

_INT_RE = re.compile(r"^[+-]?[0-9]+$")
_FLOAT_RE = re.compile(r"^[+-]?(?:[0-9]*\.[0-9]+|[0-9]+\.[0-9]*|[0-9]+[eE][+-]?[0-9]+)$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_KEY_RE = re.compile(r"^(?P<key>[^:#\[\]{},]+?)\s*:(?:\s+(?P<value>.*))?$")


def _direct_child(parent: str, candidate: str) -> bool:
    """True when ``candidate`` is a direct child path of ``parent``."""
    if parent == "$":
        return candidate != "$" and "." not in candidate and "[" not in candidate
    if not candidate.startswith(parent):
        return False
    rest = candidate[len(parent):]
    if rest.startswith("."):
        return "." not in rest[1:] and "[" not in rest[1:]
    if rest.startswith("["):
        closing = rest.find("]")
        return closing == len(rest) - 1
    return False


class _Tok:
    __slots__ = ("indent", "text", "line")

    def __init__(self, indent: int, text: str, line: int) -> None:
        self.indent = indent
        self.text = text
        self.line = line

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "_Tok(%d, %r, line=%d)" % (self.indent, self.text, self.line)


def _strip_comment(text: str) -> str:
    """Remove a trailing ``#`` comment that is not inside quotes."""
    quote = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            i += 1
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
        i += 1
    return text.rstrip()


def _balanced(text: str) -> bool:
    depth = 0
    quote = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        i += 1
    return depth <= 0 and quote is None


def _tokenize(source: str) -> List[_Tok]:
    """Split into logical lines; multi-line flow collections are joined."""
    raw = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if raw and raw[-1] == "":
        raw.pop()
    toks: List[_Tok] = []
    i = 0
    n = len(raw)
    while i < n:
        line = raw[i]
        stripped = line.strip()
        if stripped == "...":
            # A document-end marker is tolerated (PyYAML accepts it too).
            i += 1
            continue
        if stripped == "---":
            if toks:
                raise SplitError(
                    "file contains more than one YAML document; GitHub Actions "
                    "workflows must be a single document", i + 1)
            i += 1
            continue
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        text = _strip_comment(stripped)
        if not text:
            i += 1
            continue
        start = i
        # Join continuation lines while a flow collection is still open.
        guard = 0
        while not _balanced(text) and i + 1 < n and guard < 5000:
            i += 1
            guard += 1
            nxt = _strip_comment(raw[i].strip())
            text = text + " " + nxt
        if not _balanced(text):
            raise YamlError("unbalanced flow collection starting here", start + 1)
        toks.append(_Tok(indent, text, start + 1))
        i += 1
    if not toks:
        raise YamlError("document contains no YAML content (empty or comments only)")
    return toks


def _split_flow_items(body: str) -> List[str]:
    items: List[str] = []
    depth = 0
    quote = None
    cur = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and quote == '"':
                if i + 1 < n:
                    cur.append(body[i + 1])
                    i += 2
                    continue
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            items.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        items.append(tail)
    return items


def _split_key_value(text: str) -> Optional[Tuple[str, str]]:
    """Split ``key: value`` at the first colon that ends a key."""
    quote = None
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth == 0:
            nxt = text[i + 1] if i + 1 < n else " "
            if nxt in " \t":
                return text[:i].strip(), text[i + 1:].strip()
        i += 1
    return None


def _unescape_double(body: str) -> str:
    out = []
    i = 0
    n = len(body)
    simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\",
              '"': '"', "/": "/", "b": "\b", "f": "\f"}
    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n:
            nxt = body[i + 1]
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt == "u" and i + 5 < n:
                try:
                    out.append(chr(int(body[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
        out.append(ch)
        i += 1
    return "".join(out)


def _scalar(raw: str, where: str = "value") -> Any:
    text = raw.strip()
    if text == "":
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        body = text[1:-1]
        if text[0] == "'":
            return body.replace("''", "'")
        return _unescape_double(body)
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_scalar(item, where) for item in _split_flow_items(inner)]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        if not inner:
            return {}
        out: Dict[str, Any] = {}
        for item in _split_flow_items(inner):
            pair = _split_key_value(item)
            if pair is None:
                if ":" in item:
                    k, v = item.split(":", 1)
                    out[str(_scalar(k, "key"))] = _scalar(v, where)
                    continue
                raise YamlError("cannot parse flow mapping entry %r" % item)
            out[str(_scalar(pair[0], "key"))] = _scalar(pair[1], where)
        return out
    if text in _NULLS:
        return None
    if text in _TRUE_11:
        return True
    if text in _FALSE_11:
        return False
    if _INT_RE.match(text):
        try:
            return int(text)
        except ValueError:  # pragma: no cover - regex already bounds this
            return text
    if _HEX_RE.match(text):
        return int(text, 16)
    if _FLOAT_RE.match(text):
        try:
            return float(text)
        except ValueError:  # pragma: no cover
            return text
    return text


class _NativeReader:
    """Recursive-descent reader over the logical token list."""

    def __init__(self, toks: List[_Tok], raw_lines: List[str]) -> None:
        self.toks = toks
        self.pos = 0
        self.raw = raw_lines
        self.lines: Dict[str, int] = {}

    # -- helpers ---------------------------------------------------------
    def _peek(self) -> Optional[_Tok]:
        if self.pos < len(self.toks):
            return self.toks[self.pos]
        return None

    def _record(self, path: str, line: int) -> None:
        if path and path not in self.lines:
            self.lines[path] = line

    def _first_line_for(self, path: str, fallback: int) -> int:
        """Line of the first token belonging to ``path``.

        PyYAML reports a container node's start mark as the line of its first
        child, not the line of the key that introduced it.  Matching that
        convention keeps the two backends reporting identical line numbers for
        container paths such as ``jobs.<id>``.
        """
        # Direct children only: their entries already resolved recursively, so
        # the minimum is the first child's line. The path's own entry is
        # excluded -- it still holds the key's line at this point.
        children = [line for recorded, line in self.lines.items()
                    if _direct_child(path, recorded)]
        if children:
            return min(children)
        return fallback

    def _block_scalar(self, tok: _Tok, header: str) -> str:
        """Consume the indented block that follows a ``|``/``>`` header."""
        style = header[0]
        chomp = ""
        explicit_indent = 0
        for ch in header[1:].strip():
            if ch in "+-":
                chomp = ch
            elif ch.isdigit():
                explicit_indent = int(ch)
        body: List[str] = []
        if self.pos >= len(self.toks):
            return ""
        indent = self.toks[self.pos].indent
        if explicit_indent:
            indent = tok.indent + explicit_indent
        while self.pos < len(self.toks) and self.toks[self.pos].indent >= indent:
            body.append(self.raw[self.toks[self.pos].line - 1][indent:])
            self.pos += 1
        if style == "|":
            text = "\n".join(body)
        else:
            folded: List[str] = []
            for entry in body:
                if not entry.strip():
                    folded.append("\n")
                elif folded and not folded[-1].endswith("\n"):
                    folded.append(" " + entry)
                else:
                    folded.append(entry)
            text = "".join(folded)
        if chomp == "-":
            text = text.rstrip("\n")
        elif chomp == "+":
            text = text + "\n"
        else:
            text = text.rstrip("\n") + "\n" if text else ""
        return text

    def _scalar_or_block(self, tok: _Tok, raw: str) -> Any:
        raw = raw.strip()
        if raw and raw[0] in "|>":
            return self._block_scalar(tok, raw)
        return _scalar(raw)

    # -- structure -------------------------------------------------------
    def read_document(self) -> Any:
        tok = self._peek()
        if tok is None:
            return None
        if tok.text.startswith("- ") or tok.text == "-":
            return self._read_sequence(tok.indent, "$")
        return self._read_mapping(tok.indent, "$")

    def _read_mapping(self, indent: int, base: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        while True:
            tok = self._peek()
            if tok is None or tok.indent < indent:
                break
            if tok.indent > indent:
                raise YamlError("unexpected indentation for key %r" % tok.text, tok.line)
            if tok.text.startswith("- ") or tok.text == "-":
                break
            pair = _split_key_value(tok.text)
            if pair is None:
                raise YamlError("expected 'key: value' but found %r" % tok.text, tok.line)
            key_raw, value_raw = pair
            key = _scalar(key_raw, "key")
            key = key_raw if key is None else key
            key = str(key)
            if key in out:
                raise YamlError("duplicate mapping key %r" % key, tok.line)
            path = base + "." + key if base != "$" else key
            self._record(path, tok.line)
            self.pos += 1
            value_raw = value_raw.strip()
            if value_raw and value_raw[0] in "|>":
                out[key] = self._scalar_or_block(tok, value_raw)
                continue
            if value_raw:
                out[key] = _scalar(value_raw)
                continue
            nxt = self._peek()
            if nxt is None or nxt.indent <= indent:
                out[key] = None
                continue
            out[key] = self._read_block(nxt, path)
            # Overwrite (not _record): the key line was stored first, and a
            # container must report its first child's line, as PyYAML does.
            self.lines[path] = self._first_line_for(path, tok.line)
        return out

    def _read_sequence(self, indent: int, base: str) -> List[Any]:
        out: List[Any] = []
        while True:
            tok = self._peek()
            if tok is None or tok.indent < indent:
                break
            if tok.indent > indent or not (tok.text.startswith("- ") or tok.text == "-"):
                break
            item_path = "%s[%d]" % (base, len(out))
            self._record(item_path, tok.line)
            rest = tok.text[1:].strip()
            pending_item = item_path
            item_indent = tok.indent
            if rest == "":
                self.pos += 1
                nxt = self._peek()
                if nxt is None or nxt.indent <= item_indent:
                    out.append(None)
                else:
                    out.append(self._read_block(nxt, item_path))
                    self.lines[pending_item] = self._first_line_for(
                        pending_item, tok.line)
                continue
            pair = _split_key_value(rest)
            if pair is not None and rest[0] not in "[{|>'\"":
                # Inline first key of a mapping item: "- name: build".
                # The mapping continues at a deeper indent than the dash, so
                # its keys are at max(item_indent + 1, key column).
                key_indent = max(item_indent + 1, self._key_column(tok, rest))
                out.append(self._read_mapping_from(tok, rest, key_indent, item_path))
                continue
            self.pos += 1
            if rest[0] in "|>":
                out.append(self._scalar_or_block(tok, rest))
            else:
                out.append(_scalar(rest))
                # A plain scalar item may be followed by extra indented keys.
                nxt = self._peek()
                if nxt is not None and nxt.indent > item_indent and not nxt.text.startswith("- "):
                    raise YamlError(
                        "unexpected indented block after scalar list item", nxt.line
                    )
        return out

    def _key_column(self, tok: _Tok, rest: str) -> int:
        """Column of the first key written after a ``-`` sequence entry."""
        raw = self.raw[tok.line - 1]
        dash = raw.find("-")
        if dash < 0:
            return tok.indent + 2
        offset = raw.find(rest[:1], dash)
        if offset < 0:
            return tok.indent + 2
        return offset

    def _read_mapping_from(self, tok: _Tok, first_text: str, indent: int,
                           base: str) -> Dict[str, Any]:
        """Read a mapping whose first entry is the rest of ``tok``."""
        out: Dict[str, Any] = {}
        text = first_text
        line = tok.line
        self.pos += 1
        while True:
            pair = _split_key_value(text)
            if pair is None:
                raise YamlError("expected 'key: value' but found %r" % text, line)
            key_raw, value_raw = pair
            key = _scalar(key_raw, "key")
            key = key_raw if key is None else key
            key = str(key)
            if key in out:
                raise YamlError("duplicate mapping key %r" % key, line)
            path = base + "." + key
            self._record(path, line)
            if value_raw:
                if value_raw.strip()[0] in "|>":
                    out[key] = self._scalar_or_block(tok, value_raw)
                else:
                    out[key] = _scalar(value_raw)
            else:
                nxt = self._peek()
                if nxt is None or nxt.indent <= indent:
                    out[key] = None
                else:
                    out[key] = self._read_block(nxt, path)
                    self.lines[path] = self._first_line_for(path, line)
            nxt = self._peek()
            if nxt is None or nxt.indent < indent:
                break
            if not (nxt.text.startswith("- ") or nxt.text == "-") and nxt.indent > indent:
                raise YamlError("unexpected indentation for key %r" % nxt.text, nxt.line)
            if nxt.text.startswith("- ") or nxt.text == "-":
                break
            text = nxt.text
            line = nxt.line
            self.pos += 1
        return out

    def _read_block(self, tok: _Tok, base: str) -> Any:
        if tok.text.startswith("- ") or tok.text == "-":
            return self._read_sequence(tok.indent, base)
        return self._read_mapping(tok.indent, base)


def load_native(source: str) -> Tuple[Any, Dict[str, int]]:
    """Parse workflow-style YAML without any third-party dependency."""
    raw_lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    toks = _tokenize(source)
    reader = _NativeReader(toks, raw_lines)
    data = reader.read_document()
    if reader.pos < len(toks):
        leftover = toks[reader.pos]
        raise YamlError("could not parse rest of document at %r" % leftover.text, leftover.line)
    return data, reader.lines


# --------------------------------------------------------------------------
# PyYAML backend
# --------------------------------------------------------------------------


def _pyyaml_load(source: str) -> Tuple[Any, Dict[str, int]]:
    lines: Dict[str, int] = {}

    def walk(node: Any, path: str) -> None:
        if path:
            lines[path] = node.start_mark.line + 1
        if isinstance(node, _pyyaml.MappingNode):
            for key_node, value_node in node.value:
                key = str(key_node.value)
                child = path + "." + key if path else key
                walk(value_node, child)
        elif isinstance(node, _pyyaml.SequenceNode):
            for index, item in enumerate(node.value):
                walk(item, "%s[%d]" % (path, index))

    docs = []
    try:
        for doc in _pyyaml.compose_all(source):
            docs.append(doc)
    except _pyyaml.YAMLError as exc:
        line = None
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            line = mark.line + 1
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise YamlError(str(problem), line) from exc
    real = [d for d in docs if d is not None]
    if not real:
        raise YamlError("document contains no YAML content (empty or comments only)")
    if len(real) > 1:
        raise SplitError("file contains %d YAML documents; GitHub Actions "
                         "workflows must be a single document" % len(real))
    root = real[0]
    walk(root, "")
    data = _pyyaml.safe_load(source)
    return data, lines


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def load_string(source: str, prefer_native: bool = False) -> Tuple[Any, Dict[str, int], str]:
    """Parse one YAML document.

    Returns ``(data, lines, backend_used)``.  Raises :class:`YamlError` (or
    :class:`SplitError`) on malformed input.
    """
    if _pyyaml is not None and not prefer_native:
        data, lines = _pyyaml_load(source)
        return data, lines, "pyyaml"
    data, lines = load_native(source)
    return data, lines, "native"


def load_file(path: str, prefer_native: bool = False) -> Tuple[Any, Dict[str, int], str]:
    """Read and parse ``path`` as a single YAML document."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        raise YamlError("cannot read %s: %s" % (path, exc)) from exc
    if source.startswith("\ufeff"):
        source = source[1:]
    return load_string(source, prefer_native=prefer_native)


# --------------------------------------------------------------------------
# `on:` handling -- the YAML 1.1 boolean trap
# --------------------------------------------------------------------------

ON_KEY_STR = "on"
ON_KEY_BOOL = True
ON_KEY_NONE = None


def on_key_kind(data: Any) -> Optional[str]:
    """How the trigger key was parsed: ``'on'``, ``'true'`` or ``None``.

    ``'true'`` means the trigger key arrived as a boolean-ish truth value
    instead of the string ``"on"`` -- which is exactly what a YAML 1.1 reader
    (PyYAML) does to an unquoted ``on:`` key.  Both the real boolean ``True``
    and the string ``"True"`` are recognised, so the report can state which
    spelling a reader produced.
    """
    if not isinstance(data, dict):
        return None
    if "on" in data:
        return "on"
    if True in data or "True" in data:
        return "true"
    return None


def get_workflow_triggers(data: Any) -> Optional[Any]:
    """Return the value of the workflow trigger key, whatever its spelling.

    Accepts the string ``"on"``, the boolean ``True`` and the string
    ``"True"``, so that both YAML 1.1 behaviour (``on:`` -> ``True``) and
    strict-string behaviour work with either backend.
    """
    if not isinstance(data, dict):
        return None
    if "on" in data:
        return data["on"]
    if True in data:
        return data[True]
    if "True" in data:
        return data["True"]
    return None


def trigger_names(value: Any) -> List[str]:
    """Normalise a trigger value into a list of event names."""
    names: List[str] = []
    if value is None:
        return names
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                names.extend(str(k) for k in item)
        return names
    if isinstance(value, dict):
        return [str(k) for k in value]
    return names
