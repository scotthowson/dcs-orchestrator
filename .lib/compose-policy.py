#!/usr/bin/env python3
# =============================================================================
# compose-policy.py — the YAML side of the compose policy (.lib/compose-policy.sh)
#
#   compose-policy.py raw FILE DIR [ENV_FILE] < compose-config.json
#       Docker Compose judged the file (`docker compose config --format json` on stdin): adds what that output no
#       longer shows (the files an include:, an extends: or an env_file: names, a line number per service key) and
#       where each host path really leads (links followed). Prints {"config": ..., "raw": ...}.
#   compose-policy.py resolve FILE DIR [ENV_FILE]
#       No Docker Compose: the same {"config", "raw"} from the file itself — YAML read (PyYAML when it is there, else
#       the small reader below: block and flow style, anchors, aliases, merge keys, block scalars), ${VAR} filled in
#       from ENV_FILE and the environment the way Compose does, include:/extends: followed, the short forms turned
#       into the long ones Compose prints (volumes, devices, build, sysctls, environment).
#
# Never runs anything it reads. DCS_POLICY_PYYAML=0 forces the small reader (the tests use it).
# =============================================================================
import json
import os
import re
import sys

MAX_DEPTH = 5


class YamlError(Exception):
    pass


# -----------------------------------------------------------------------------
# A small YAML reader: what compose files are written in. Returns (data, lines) where lines maps a key path
# ("services/web/privileged") to its 1-based line.
# -----------------------------------------------------------------------------
class MiniYaml:
    def __init__(self, text):
        if text.startswith('﻿'):
            text = text[1:]
        self.lines = [ln.rstrip('\r') for ln in text.split('\n')]
        self.n = len(self.lines)
        self.i = 0
        self.anchors = {}
        self.linemap = {}

    # ---- helpers ----
    @staticmethod
    def indent_of(line):
        return len(line) - len(line.lstrip(' '))

    @staticmethod
    def strip_comment(s):
        # a # that starts a comment: at the start or after a blank, outside quotes
        out, q, i = [], None, 0
        while i < len(s):
            c = s[i]
            if q:
                out.append(c)
                if q == "'" and c == "'":
                    if i + 1 < len(s) and s[i + 1] == "'":
                        out.append("'")
                        i += 1
                    else:
                        q = None
                elif q == '"' and c == '\\' and i + 1 < len(s):
                    out.append(s[i + 1])
                    i += 1
                elif q == '"' and c == '"':
                    q = None
            else:
                if c == '#' and (i == 0 or s[i - 1] in ' \t'):
                    break
                if c in '"\'' and (i == 0 or s[i - 1] in ' \t[{,:-'):
                    q = c
                out.append(c)
            i += 1
        return ''.join(out).rstrip()

    def skip(self):
        while self.i < self.n:
            ln = self.lines[self.i]
            st = ln.strip()
            if st == '' or st.startswith('#') or (self.indent_of(ln) == 0 and (st == '---' or st.startswith('%') or st.startswith('--- '))):
                if st.startswith('--- '):
                    rest = st[4:].strip()
                    if rest and not rest.startswith('#'):
                        self.lines[self.i] = rest
                        return
                self.i += 1
                continue
            if self.indent_of(ln) == 0 and st == '...':
                self.i = self.n
                return
            return

    def split_key(self, content):
        """('key', rest) when the line content is `key: rest`, else None."""
        # a flow collection, an alias, a block scalar or a sequence item is not a key (nor is `&anchor key: v`)
        if not content or content[0] in '[{&*!|>%@`' or content.startswith('- ') or content == '-':
            return None
        if content.startswith('? '):
            raise YamlError('line %d: complex keys are not supported' % (self.i + 1))
        if content[0] in '"\'':
            q = content[0]
            j = 1
            buf = []
            while j < len(content):
                c = content[j]
                if q == "'" and c == "'":
                    if j + 1 < len(content) and content[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    break
                if q == '"' and c == '\\' and j + 1 < len(content):
                    buf.append(self.unescape('\\' + content[j + 1]))
                    j += 2
                    continue
                if q == '"' and c == '"':
                    break
                buf.append(c)
                j += 1
            rest = content[j + 1:].lstrip(' ')
            if rest.startswith(':') and (len(rest) == 1 or rest[1] in ' \t'):
                return ''.join(buf), rest[1:].strip()
            return None
        m = re.match(r'^([^#]*?)\s*:(?:\s+|$)(.*)$', content)
        if not m:
            return None
        key = m.group(1)
        if key == '' or key.startswith('#'):
            return None
        if '{' in key or '[' in key:
            return None
        return key, m.group(2)

    @staticmethod
    def unescape(s):
        table = {'n': '\n', 't': '\t', 'r': '\r', '0': '\0', '"': '"', '\\': '\\', '/': '/', ' ': ' ', 'a': '\a', 'b': '\b', 'e': '\x1b', 'f': '\f', 'v': '\v', 'N': '\x85', '_': '\xa0'}
        out, i = [], 0
        while i < len(s):
            c = s[i]
            if c == '\\' and i + 1 < len(s):
                d = s[i + 1]
                if d in table:
                    out.append(table[d])
                    i += 2
                    continue
                for ch, ln in (('x', 2), ('u', 4), ('U', 8)):
                    if d == ch:
                        try:
                            out.append(chr(int(s[i + 2:i + 2 + ln], 16)))
                        except ValueError:
                            out.append(s[i:i + 2 + ln])
                        i += 2 + ln
                        break
                else:
                    out.append(d)
                    i += 2
                continue
            out.append(c)
            i += 1
        return ''.join(out)

    @staticmethod
    def scalar(s, quoted=False):
        if quoted:
            return s
        t = s.strip()
        if t in ('', '~', 'null', 'Null', 'NULL'):
            return None
        if t in ('true', 'True', 'TRUE'):
            return True
        if t in ('false', 'False', 'FALSE'):
            return False
        if re.match(r'^[-+]?[0-9]+$', t):
            try:
                return int(t)
            except ValueError:
                return t
        if re.match(r'^[-+]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$', t):
            try:
                return float(t)
            except ValueError:
                return t
        return t

    def take_props(self, rest):
        """Leading &anchor and !tag of a value: (anchor, rest)."""
        anchor = None
        while True:
            rest = rest.lstrip(' ')
            m = re.match(r'^&([^\s,\[\]{}]+)\s*(.*)$', rest)
            if m:
                anchor, rest = m.group(1), m.group(2)
                continue
            m = re.match(r'^!(?:![^\s]*|[^\s,\[\]{}]*)\s*(.*)$', rest)
            if m and rest.startswith('!'):
                rest = m.group(1)
                continue
            return anchor, rest

    # ---- block structure ----
    def parse_document(self):
        self.skip()
        if self.i >= self.n:
            return None
        v = self.parse_node(0, ())
        self.skip()
        if self.i < self.n:
            raise YamlError('line %d: unexpected content' % (self.i + 1))
        return v

    def parse_node(self, min_indent, path):
        self.skip()
        if self.i >= self.n:
            return None
        ln = self.lines[self.i]
        ind = self.indent_of(ln)
        if ind < min_indent:
            return None
        content = ln[ind:]
        if content.startswith('- ') or content == '-':
            return self.parse_seq(ind, path)
        if self.split_key(self.strip_comment(content)) is not None:
            return self.parse_map(ind, path)
        self.i += 1
        return self.parse_value(content, ind - 1, path)

    def parse_map(self, ind, path):
        result, merges = {}, []
        while True:
            self.skip()
            if self.i >= self.n:
                break
            ln = self.lines[self.i]
            li = self.indent_of(ln)
            if li < ind:
                break
            if li > ind:
                raise YamlError('line %d: unexpected indentation' % (self.i + 1))
            content = self.strip_comment(ln[ind:])
            if content.startswith('- ') or content == '-':
                break
            kv = self.split_key(content)
            if kv is None:
                raise YamlError('line %d: expected "key: value"' % (self.i + 1))
            key, rest = kv
            self.linemap.setdefault('/'.join(path + (key,)), self.i + 1)
            self.i += 1
            value = self.parse_value(rest, ind, path + (key,), compact_seq_ok=True)
            if key == '<<':
                merges.append(value)
            else:
                result[key] = value
        return self.apply_merges(result, merges)

    @staticmethod
    def apply_merges(result, merges):
        if not merges:
            return result
        merged = {}
        for m in merges:
            for src in (m if isinstance(m, list) else [m]):
                if isinstance(src, dict):
                    for k, v in src.items():
                        merged.setdefault(k, v)
        merged.update(result)
        return merged

    def parse_seq(self, ind, path):
        result = []
        while True:
            self.skip()
            if self.i >= self.n:
                break
            ln = self.lines[self.i]
            li = self.indent_of(ln)
            content = ln[li:]
            if li != ind or not (content.startswith('- ') or content.rstrip() == '-'):
                if li > ind:
                    raise YamlError('line %d: unexpected indentation' % (self.i + 1))
                break
            after = content[1:]
            rest = after.lstrip(' ')
            col = li + 1 + (len(after) - len(rest))
            idx = len(result)
            if self.strip_comment(rest) == '':
                self.i += 1
                item = self.parse_node(ind + 1, path + (str(idx),))
            else:
                anchor, r2 = self.take_props(rest)
                if anchor is not None and self.strip_comment(r2) == '':
                    self.i += 1
                    item = self.parse_node(ind + 1, path + (str(idx),))
                elif r2.startswith('- ') or r2.rstrip() == '-' or self.split_key(self.strip_comment(r2)) is not None:
                    self.lines[self.i] = ' ' * (col + len(rest) - len(r2)) + r2
                    item = self.parse_node(col, path + (str(idx),))
                else:
                    self.i += 1
                    item = self.parse_value(r2, ind, path + (str(idx),))
                if anchor is not None:
                    self.anchors[anchor] = item
            result.append(item)
        return result

    def parse_value(self, rest, ind, path, compact_seq_ok=False):
        """The value after `key:` (or `- `) whose line is already consumed; ind = the indentation of the key."""
        anchor, rest = self.take_props(rest)
        body = self.strip_comment(rest)
        if body == '':
            self.skip()
            value = None
            if self.i < self.n:
                ln = self.lines[self.i]
                li = self.indent_of(ln)
                c = ln[li:]
                if li > ind:
                    value = self.parse_node(ind + 1, path)
                elif compact_seq_ok and li == ind and (c.startswith('- ') or c.rstrip() == '-'):
                    value = self.parse_seq(ind, path)
        elif body[0] in '|>':
            value = self.block_scalar(body, ind)
        elif body[0] == '*':
            name = body[1:].strip()
            if name not in self.anchors:
                raise YamlError('line %d: unknown alias *%s' % (self.i, name))
            value = self.anchors[name]
        elif body[0] in '[{':
            text = rest
            while not self.flow_complete(text):
                if self.i >= self.n:
                    raise YamlError('an unclosed %s' % body[0])
                text += '\n' + self.lines[self.i]
                self.i += 1
            value, pos = self.flow_value(text, 0)
            tail = self.strip_comment(text[pos:]).strip()
            if tail:
                raise YamlError('line %d: unexpected text after a flow collection' % self.i)
        elif body[0] in '"\'':
            text = rest.lstrip(' ')
            while True:
                end = self.quote_end(text)
                if end is not None:
                    break
                if self.i >= self.n:
                    raise YamlError('an unclosed quote')
                text += '\n' + self.lines[self.i]
                self.i += 1
            value = self.quoted(text[:end + 1])
        else:
            parts = [body]
            while self.i < self.n:
                ln = self.lines[self.i]
                st = ln.strip()
                if st == '' or st.startswith('#') or self.indent_of(ln) <= ind:
                    break
                parts.append(self.strip_comment(st))
                self.i += 1
            value = self.scalar(' '.join(parts))
        if anchor is not None:
            self.anchors[anchor] = value
        return value

    def block_scalar(self, header, ind):
        m = re.match(r'^([|>])([-+]?)([1-9]?)([-+]?)\s*$', header)
        if not m:
            raise YamlError('line %d: a block scalar header' % self.i)
        style, chomp = m.group(1), (m.group(2) or m.group(4))
        lines = []
        content_ind = (ind + int(m.group(3))) if m.group(3) else None
        while self.i < self.n:
            ln = self.lines[self.i]
            if ln.strip() == '':
                lines.append('')
                self.i += 1
                continue
            li = self.indent_of(ln)
            if li <= ind:
                break
            if content_ind is None:
                content_ind = li
            if li < content_ind:
                break
            lines.append(ln[content_ind:])
            self.i += 1
        while lines and lines[-1] == '' and chomp != '+':
            lines.pop()
        if style == '|':
            text = '\n'.join(lines)
        else:
            # folded: neighbouring lines join with a space, blank lines and more-indented lines keep their breaks
            text, blanks, first, prev_more = '', 0, True, False
            for ln in lines:
                if ln == '':
                    blanks += 1
                    continue
                more = ln[0] in ' \t'
                if first:
                    text += '\n' * blanks + ln
                    first = False
                elif more or prev_more:
                    text += '\n' + '\n' * blanks + ln
                elif blanks:
                    text += '\n' * blanks + ln
                else:
                    text += ' ' + ln
                blanks, prev_more = 0, more
        if chomp != '-' and lines:
            text += '\n'
        return text

    @staticmethod
    def quote_end(text):
        q = text[0]
        j = 1
        while j < len(text):
            c = text[j]
            if q == "'" and c == "'":
                if j + 1 < len(text) and text[j + 1] == "'":
                    j += 2
                    continue
                return j
            if q == '"' and c == '\\':
                j += 2
                continue
            if q == '"' and c == '"':
                return j
            j += 1
        return None

    def quoted(self, text):
        q, inner = text[0], text[1:-1]
        # line breaks inside quotes fold to a space
        inner = re.sub(r'[ \t]*\n[ \t]*', ' ', inner)
        if q == "'":
            return inner.replace("''", "'")
        return self.unescape(inner)

    @staticmethod
    def flow_complete(text):
        depth, q, i = 0, None, 0
        started = False
        while i < len(text):
            c = text[i]
            if q:
                if q == "'" and c == "'":
                    if i + 1 < len(text) and text[i + 1] == "'":
                        i += 2
                        continue
                    q = None
                elif q == '"' and c == '\\':
                    i += 2
                    continue
                elif q == '"' and c == '"':
                    q = None
            else:
                if c == '#' and (i == 0 or text[i - 1] in ' \t\n'):
                    nl = text.find('\n', i)
                    if nl < 0:
                        break
                    i = nl
                    continue
                if c in '"\'' and (i == 0 or text[i - 1] in ' \t\n[{,:'):
                    q = c
                elif c in '[{':
                    depth += 1
                    started = True
                elif c in ']}':
                    depth -= 1
                    if started and depth == 0:
                        return True
            i += 1
        return False

    def flow_ws(self, text, pos):
        while pos < len(text):
            c = text[pos]
            if c in ' \t\n\r':
                pos += 1
            elif c == '#' and (pos == 0 or text[pos - 1] in ' \t\n'):
                nl = text.find('\n', pos)
                pos = len(text) if nl < 0 else nl
            else:
                break
        return pos

    def flow_value(self, text, pos):
        pos = self.flow_ws(text, pos)
        anchor = None
        while pos < len(text) and text[pos] in '&!':
            m = re.match(r'[&!][^\s,\[\]{}]*', text[pos:])
            if text[pos] == '&':
                anchor = m.group(0)[1:]
            pos = self.flow_ws(text, pos + len(m.group(0)))
        if pos >= len(text):
            raise YamlError('an unfinished flow collection')
        c = text[pos]
        if c == '[':
            value, pos = self.flow_seq(text, pos + 1)
        elif c == '{':
            value, pos = self.flow_map(text, pos + 1)
        elif c in '"\'':
            end = self.quote_end(text[pos:])
            if end is None:
                raise YamlError('an unclosed quote')
            value = self.quoted(text[pos:pos + end + 1])
            pos += end + 1
        elif c == '*':
            m = re.match(r'\*([^\s,\[\]{}]+)', text[pos:])
            if not m or m.group(1) not in self.anchors:
                raise YamlError('an unknown alias in a flow collection')
            value = self.anchors[m.group(1)]
            pos += len(m.group(0))
        else:
            value, pos = self.flow_plain(text, pos)
        if anchor is not None:
            self.anchors[anchor] = value
        return value, pos

    def flow_plain(self, text, pos, key=False):
        start = pos
        while pos < len(text):
            c = text[pos]
            if c in ',[]{}':
                break
            if c == ':' and (pos + 1 >= len(text) or text[pos + 1] in ' \t\n,[]{}'):
                break
            if c == '#' and text[pos - 1] in ' \t\n':
                break
            pos += 1
        raw = re.sub(r'\s*\n\s*', ' ', text[start:pos]).strip()
        return (raw if key else self.scalar(raw)), pos

    def flow_seq(self, text, pos):
        out = []
        while True:
            pos = self.flow_ws(text, pos)
            if pos >= len(text):
                raise YamlError('an unclosed [')
            if text[pos] == ']':
                return out, pos + 1
            item, pos = self.flow_value(text, pos)
            pos = self.flow_ws(text, pos)
            if pos < len(text) and text[pos] == ':':   # [a: b] is a one-pair map
                val, pos = self.flow_value(text, pos + 1)
                item = {str(item): val}
                pos = self.flow_ws(text, pos)
            out.append(item)
            if pos < len(text) and text[pos] == ',':
                pos += 1
            elif pos < len(text) and text[pos] == ']':
                continue
            else:
                raise YamlError('a flow sequence without a comma')

    def flow_map(self, text, pos):
        out, merges = {}, []
        while True:
            pos = self.flow_ws(text, pos)
            if pos >= len(text):
                raise YamlError('an unclosed {')
            if text[pos] == '}':
                return self.apply_merges(out, merges), pos + 1
            if text[pos] in '"\'':
                end = self.quote_end(text[pos:])
                if end is None:
                    raise YamlError('an unclosed quote')
                key = self.quoted(text[pos:pos + end + 1])
                pos += end + 1
            else:
                key, pos = self.flow_plain(text, pos, key=True)
            pos = self.flow_ws(text, pos)
            value = None
            if pos < len(text) and text[pos] == ':':
                value, pos = self.flow_value(text, pos + 1)
                pos = self.flow_ws(text, pos)
            if key == '<<':
                merges.append(value)
            else:
                out[key] = value
            if pos < len(text) and text[pos] == ',':
                pos += 1
            elif pos < len(text) and text[pos] == '}':
                continue
            else:
                raise YamlError('a flow mapping without a comma')


def load_yaml(text):
    """(data, linemap, reader)"""
    if os.environ.get('DCS_POLICY_PYYAML', '1') != '0':
        try:
            import yaml  # noqa: F401
        except ImportError:
            yaml = None
        if yaml is not None:
            return load_pyyaml(yaml, text)
    p = MiniYaml(text)
    return p.parse_document(), p.linemap, 'builtin'


def load_pyyaml(yaml, text):
    class Loader(yaml.SafeLoader):
        pass

    # Compose's own tags: the value is what counts here
    def _tagged(loader, suffix, node):
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node, deep=True)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_scalar(node)
    Loader.add_multi_constructor('!', _tagged)
    # YAML 1.1 reads yes/no/on/off as booleans; Compose (YAML 1.2) reads them as text: keep them text
    Loader.yaml_implicit_resolvers = {k: [(t, r) for (t, r) in v if t != 'tag:yaml.org,2002:bool'] for k, v in Loader.yaml_implicit_resolvers.items()}
    Loader.add_implicit_resolver('tag:yaml.org,2002:bool', re.compile(r'^(?:true|True|TRUE|false|False|FALSE)$'), list('tTfF'))
    try:
        loader = Loader(text)
        try:
            node = loader.get_single_node()
            data = loader.construct_document(node) if node is not None else None
        finally:
            loader.dispose()
    except yaml.YAMLError as e:
        raise YamlError(str(e).replace('\n', ' '))
    linemap = {}

    def walk(n, path, depth):
        if depth > 3 or not isinstance(n, yaml.MappingNode):
            return
        for k, v in n.value:
            if isinstance(k, yaml.ScalarNode):
                p = path + (str(k.value),)
                linemap.setdefault('/'.join(p), k.start_mark.line + 1)
                walk(v, p, depth + 1)
    if node is not None:
        walk(node, (), 0)
    return data, linemap, 'pyyaml'


# -----------------------------------------------------------------------------
# Interpolation the way Compose does it
# -----------------------------------------------------------------------------
def read_dotenv(path):
    env = {}
    if not path or not os.path.isfile(path):
        return env
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError:
        return env
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        m = re.match(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$', s)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
            v = v[1:-1]
            if s[s.index('=') + 1:].strip().startswith('"'):
                v = v.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
        elif v.startswith(('"', "'")) and v[0] in v[1:]:
            q = v[0]
            v = v[1:v.index(q, 1)]
        else:
            v = re.sub(r'\s+#.*$', '', v).strip()
        env[k] = v
    # values may name earlier ones (${OTHER})
    for k in list(env):
        env[k] = interpolate(env[k], dict(env, **{x: y for x, y in os.environ.items()}))
    return env


def interpolate(s, env):
    if not isinstance(s, str) or '$' not in s:
        return s
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c != '$':
            out.append(c)
            i += 1
            continue
        if s.startswith('$$', i):
            out.append('$')
            i += 2
            continue
        m = re.match(r'\$([A-Za-z_][A-Za-z0-9_]*)', s[i:])
        if m:
            out.append(env.get(m.group(1), ''))
            i += len(m.group(0))
            continue
        if s.startswith('${', i):
            depth, j = 1, i + 2
            while j < len(s) and depth:
                if s.startswith('${', j):
                    depth += 1
                    j += 2
                    continue
                if s[j] == '}':
                    depth -= 1
                j += 1
            inner = s[i + 2:j - 1]
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])(.*))?$', inner, re.S)
            if not m:
                out.append(s[i:j])
                i = j
                continue
            name, op, arg = m.group(1), m.group(2), m.group(3) or ''
            val = env.get(name)
            if op in (':-', '-'):
                use_default = val is None or (op == ':-' and val == '')
                out.append(interpolate(arg, env) if use_default else val)
            elif op in (':+', '+'):
                use_alt = val is not None and (op == '+' or val != '')
                out.append(interpolate(arg, env) if use_alt else '')
            else:
                out.append(val or '')
            i = j
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def interpolate_all(v, env):
    if isinstance(v, dict):
        return {k: interpolate_all(x, env) for k, x in v.items()}
    if isinstance(v, list):
        return [interpolate_all(x, env) for x in v]
    return interpolate(v, env)


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------
def is_remote(p):
    return bool(re.match(r'^([a-z][a-z0-9+.-]*://|git@|github\.com/|docker-image://|service:|oci-layout://)', p or ''))


def absolute(p, base):
    if not isinstance(p, str) or p == '':
        return p
    if p.startswith('~'):
        p = os.path.expanduser(p)
    if not p.startswith('/'):
        p = os.path.join(base, p)
    return os.path.normpath(p).replace('//', '/')


# -----------------------------------------------------------------------------
# The long forms Compose prints
# -----------------------------------------------------------------------------
def split_volume(spec):
    # src:dst[:mode], dst alone; a src that is a name is a named volume
    parts = spec.split(':')
    if len(parts) == 1:
        return None, parts[0], ''
    if len(parts) == 2:
        return parts[0], parts[1], ''
    return parts[0], parts[1], ':'.join(parts[2:])


def norm_volume(v, base):
    if isinstance(v, str):
        src, dst, mode = split_volume(v)
        if src is None:
            return {'type': 'volume', 'target': dst}
        opts = [o for o in re.split(r'[,]', mode) if o]
        out = {'target': dst}
        if src.startswith(('/', '.', '~')):
            out['type'] = 'bind'
            out['source'] = absolute(src, base)
        else:
            out['type'] = 'volume'
            out['source'] = src
        if 'ro' in opts:
            out['read_only'] = True
        return out
    if isinstance(v, dict):
        out = dict(v)
        t = out.get('type') or ('bind' if str(out.get('source', '')).startswith(('/', '.', '~')) else 'volume')
        out['type'] = t
        if t == 'bind' and isinstance(out.get('source'), str):
            out['source'] = absolute(out['source'], base)
        return out
    return v


def norm_device(d):
    if isinstance(d, str):
        parts = d.split(':')
        out = {'source': parts[0], 'target': parts[1] if len(parts) > 1 else parts[0]}
        if len(parts) > 2:
            out['permissions'] = parts[2]
        return out
    return d


def to_map(v, sep='='):
    if isinstance(v, dict):
        return {str(k): ('' if x is None else str(x) if not isinstance(x, bool) else str(x).lower()) for k, x in v.items()}
    out = {}
    for item in v or []:
        if isinstance(item, str):
            k, _, x = item.partition(sep)
            out[k.strip()] = x.strip()
    return out


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def norm_service(svc, base):
    s = dict(svc)
    if 'volumes' in s:
        s['volumes'] = [norm_volume(v, base) for v in as_list(s['volumes'])]
    if 'devices' in s:
        s['devices'] = [norm_device(d) for d in as_list(s['devices'])]
    for k in ('cap_add', 'cap_drop', 'security_opt', 'device_cgroup_rules', 'volumes_from', 'dns'):
        if k in s:
            s[k] = [str(x) for x in as_list(s[k])]
    if 'sysctls' in s:
        s['sysctls'] = to_map(s['sysctls'])
    if 'environment' in s:
        s['environment'] = to_map(s['environment'])
    if 'build' in s:
        b = s['build']
        if isinstance(b, str):
            b = {'context': b}
        if isinstance(b, dict):
            b = dict(b)
            ctx = b.get('context', '.')
            if isinstance(ctx, str) and not is_remote(ctx):
                b['context'] = absolute(ctx, base)
            ac = b.get('additional_contexts')
            if isinstance(ac, dict):
                b['additional_contexts'] = {k: (absolute(x, base) if isinstance(x, str) and not is_remote(x) else x) for k, x in ac.items()}
            elif isinstance(ac, list):
                b['additional_contexts'] = {str(x).partition('=')[0]: (lambda y: absolute(y, base) if not is_remote(y) else y)(str(x).partition('=')[2]) for x in ac}
        s['build'] = b
    s.pop('env_file', None)
    s.pop('extends', None)
    return s


def merge_service(base, over):
    """extends: the base service with the overriding one on top (lists are added up, maps merged)."""
    out = dict(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], list) and isinstance(v, list):
            out[k] = out[k] + v
        elif k in out and isinstance(out[k], dict) and isinstance(v, dict):
            m = dict(out[k])
            m.update(v)
            out[k] = m
        else:
            out[k] = v
    return out


# -----------------------------------------------------------------------------
# One file (and what it includes)
# -----------------------------------------------------------------------------
class Loader:
    def __init__(self, env):
        self.env = env
        self.raw = {'include': [], 'extends_files': [], 'env_files': [], 'lines': {}, 'reader': None, 'top': []}
        self.cache = {}

    def read(self, path):
        if path in self.cache:
            return self.cache[path]
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        data, lines, reader = load_yaml(text)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise YamlError('%s: the top of a compose file is a mapping' % path)
        self.cache[path] = (data, lines, reader)
        return data, lines, reader

    def note(self, data, lines, reader, base, main):
        """What the raw file says: the files it names, the lines of its services (the main file only)."""
        if main:
            self.raw['reader'] = reader
            self.raw['top'] = sorted(str(k) for k in data.keys())
            for key, line in lines.items():
                parts = key.split('/')
                if parts[0] == 'services' and len(parts) in (2, 3):
                    self.raw['lines'].setdefault(parts[1], {})['_' if len(parts) == 2 else parts[2]] = line
                elif len(parts) == 1:
                    self.raw['lines'].setdefault('_top', {})[parts[0]] = line
        for svc_name, svc in (data.get('services') or {}).items():
            if not isinstance(svc, dict):
                continue
            for ef in as_list(svc.get('env_file')):
                p = ef.get('path') if isinstance(ef, dict) else ef
                if isinstance(p, str):
                    self.raw['env_files'].append({'service': str(svc_name), 'path': absolute(interpolate(p, self.env), base)})
            ext = svc.get('extends')
            if isinstance(ext, dict) and isinstance(ext.get('file'), str):
                self.raw['extends_files'].append({'service': str(svc_name), 'path': absolute(interpolate(ext['file'], self.env), base)})

    def includes(self, data, base):
        out = []
        for inc in as_list(data.get('include')):
            if isinstance(inc, str):
                paths, pdir = [inc], None
            elif isinstance(inc, dict):
                paths, pdir = as_list(inc.get('path')), inc.get('project_directory')
            else:
                continue
            for p in paths:
                if isinstance(p, str):
                    ap = absolute(interpolate(p, self.env), base)
                    out.append((ap, absolute(interpolate(pdir, self.env), base) if isinstance(pdir, str) else os.path.dirname(ap)))
        return out

    def load(self, path, project_dir, depth=0, main=True, resolve=True):
        data, lines, reader = self.read(path)
        base = os.path.dirname(path)
        self.note(data, lines, reader, base, main)
        for ap, pd in self.includes(data, base):
            self.raw['include'].append(ap)
            if not resolve and depth < MAX_DEPTH and ap not in self.cache:
                try:
                    self.load(ap, pd, depth + 1, main=False, resolve=False)
                except (OSError, YamlError):
                    pass
        if not resolve:
            return None
        data = interpolate_all(data, self.env)
        services = {}
        volumes = dict(data.get('volumes') or {}) if isinstance(data.get('volumes'), dict) else {}
        configs = dict(data.get('configs') or {}) if isinstance(data.get('configs'), dict) else {}
        secrets = dict(data.get('secrets') or {}) if isinstance(data.get('secrets'), dict) else {}
        if depth < MAX_DEPTH:
            for ap, pd in self.includes(data, base):
                try:
                    sub = self.load(ap, pd, depth + 1, main=False)
                except (OSError, YamlError):
                    continue
                for k, v in sub['services'].items():
                    services.setdefault(k, v)
                for coll, src in ((volumes, sub.get('volumes')), (configs, sub.get('configs')), (secrets, sub.get('secrets'))):
                    for k, v in (src or {}).items():
                        coll.setdefault(k, v)
        raw_services = data.get('services') or {}
        if not isinstance(raw_services, dict):
            raw_services = {}

        def resolved(name, seen):
            svc = raw_services.get(name)
            if not isinstance(svc, dict):
                return {}
            ext = svc.get('extends')
            if isinstance(ext, str):
                ext = {'service': ext}
            if isinstance(ext, dict) and ext.get('service') and name not in seen:
                if isinstance(ext.get('file'), str) and depth < MAX_DEPTH:
                    try:
                        other = self.load(absolute(ext['file'], base), project_dir, depth + 1, main=False)
                        parent = other['services'].get(ext['service'], {})
                    except (OSError, YamlError):
                        parent = {}
                else:
                    parent = resolved(ext['service'], seen | {name})
                return merge_service(parent, svc)
            return svc

        for name in raw_services:
            services[str(name)] = norm_service(resolved(name, set()), project_dir)
        for coll in (configs, secrets):
            for k, v in list(coll.items()):
                if isinstance(v, dict) and isinstance(v.get('file'), str):
                    v = dict(v)
                    v['file'] = absolute(v['file'], project_dir)
                    coll[k] = v
        return {'services': services, 'volumes': volumes, 'configs': configs, 'secrets': secrets}


# -----------------------------------------------------------------------------
# Where host paths really lead (links followed, the rest of a path that is not there kept)
# -----------------------------------------------------------------------------
def host_paths(config, raw):
    paths = set()
    for svc in (config.get('services') or {}).values():
        if not isinstance(svc, dict):
            continue
        for v in svc.get('volumes') or []:
            if isinstance(v, dict) and v.get('type') == 'bind' and isinstance(v.get('source'), str):
                paths.add(v['source'])
        for d in svc.get('devices') or []:
            src = d.get('source') if isinstance(d, dict) else str(d).split(':')[0]
            if isinstance(src, str):
                paths.add(src)
        b = svc.get('build')
        if isinstance(b, dict):
            if isinstance(b.get('context'), str):
                paths.add(b['context'])
            for x in (b.get('additional_contexts') or {}).values():
                if isinstance(x, str):
                    paths.add(x)
    for v in (config.get('volumes') or {}).values():
        if isinstance(v, dict) and isinstance((v.get('driver_opts') or {}).get('device'), str):
            paths.add(v['driver_opts']['device'])
    for coll in ('configs', 'secrets'):
        for v in (config.get(coll) or {}).values():
            if isinstance(v, dict) and isinstance(v.get('file'), str):
                paths.add(v['file'])
    for p in raw['include']:
        paths.add(p)
    for e in raw['extends_files'] + raw['env_files']:
        paths.add(e['path'])
    out = {}
    for p in paths:
        if isinstance(p, str) and p.startswith('/'):
            try:
                out[p] = os.path.realpath(p)
            except (OSError, ValueError):
                out[p] = p
    return out


def main(argv):
    if len(argv) < 4 or argv[1] not in ('raw', 'resolve'):
        sys.stderr.write('usage: compose-policy.py raw|resolve FILE DIR [ENV_FILE]\n')
        return 2
    mode, path, pdir = argv[1], os.path.abspath(argv[2]), os.path.abspath(argv[3])
    envfile = argv[4] if len(argv) > 4 and argv[4] else None
    env = read_dotenv(envfile)
    env.update(os.environ)   # the shell's environment wins over the .env file, as in Compose
    loader = Loader(env)
    result = {'ok': True}
    config = {}
    try:
        if mode == 'raw':
            text = sys.stdin.read()
            config = json.loads(text) if text.strip() else {}
            loader.load(path, pdir, resolve=False)
        else:
            config = loader.load(path, pdir)
    except (OSError, YamlError, RecursionError, ValueError) as e:
        result = {'ok': False, 'error': str(e)[:300]}
        if mode == 'resolve':
            config = {}
    loader.raw['include'] = sorted(set(loader.raw['include']))
    raw = loader.raw
    raw['realpath'] = host_paths(config if isinstance(config, dict) else {}, raw)
    raw.update(result)
    json.dump({'config': config, 'raw': raw}, sys.stdout, default=str)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
