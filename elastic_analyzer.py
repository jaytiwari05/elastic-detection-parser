#!/usr/bin/env python3
"""
elastic_analyzer.py  —  Elastic Defend alert decoder
Answers one question: why did this binary get flagged?

Usage:
    python elastic_analyzer.py <alert.json>
    python elastic_analyzer.py <alert.json> --no-pull   # skip git pull
    python elastic_analyzer.py <alert.json> --no-color

Author: PaiN05
"""

import json, sys, os, re, io, subprocess
from datetime import datetime
from textwrap import fill

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

try:
    import tomllib
    def _toml_load(p):
        with open(p, 'rb') as f:
            return tomllib.load(f)
except ImportError:
    def _toml_load(p):
        return None

# ── config ────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_PATH  = os.path.join(SCRIPT_DIR, 'protections-artifacts')
REPO_URL   = 'https://github.com/elastic/protections-artifacts.git'

# ── color ─────────────────────────────────────────────────────────────────────
COLOR = True
def c(*codes): return ''.join(codes) if COLOR else ''
def r(): return '\033[0m' if COLOR else ''
R  = '\033[0m'
B  = '\033[1m'
D  = '\033[2m'
RE = '\033[91m'
GR = '\033[92m'
YE = '\033[93m'
BL = '\033[94m'
MA = '\033[95m'
CY = '\033[96m'
WH = '\033[97m'
OR = '\033[38;5;208m'

def _status(label, bg, fg=WH):
    if COLOR: return f"\033[{bg}m{B} {label} {R}"
    return f"[{label}]"

BLOCKED  = lambda: _status('BLOCKED',  '42', WH)
DETECTED = lambda: _status('DETECTED', '43', WH)
KILLED   = lambda: _status('KILLED',   '42', WH)
MATCHED  = lambda: _status('MATCH',    '41', WH)
SKIPD    = lambda: _status('SKIP',     '100', WH)
SMOKEGUN = lambda: _status('!!',       '41', WH)
SEV_H    = lambda: _status('HIGH',     '41', WH)
SEV_C    = lambda: _status('CRITICAL', '45', WH)
SEV_M    = lambda: _status('MEDIUM',   '43', WH)

W = 78

BANNER = r""" ___ _      _   ___ _____ ___ ___     _   _  _   _   _ __   _________ ___
| __| |    /_\ / __|_   _|_ _/ __|   /_\ | \| | /_\ | |\ \ / /_  / __| _ \
| _|| |__ / _ \\__ \ | |  | | (__   / _ \| .` |/ _ \| |_\ V / / /| _||   /
|___|____/_/ \_\___/ |_| |___\___| /_/ \_\_|\_/_/ \_\____|_| /___|___|_|_\
""".rstrip("\n")

def banner():
    print(f"{c(B,CY)}{BANNER}{c(r())}")
    print(f"{c(D)}{'Author : PaiN05'.center(W)}{c(r())}")
    print(f"{c(D)}{'─'*W}{c(r())}")

def div(title=''):
    if title:
        pad = W - len(title) - 5
        print(f"\n{c(D)}── {c(r())}{c(B,CY)}{title}{c(r())} {c(D)}{'─'*max(pad,2)}{c(r())}")
    else:
        print(f"{c(D)}{'─'*W}{c(r())}")

def kv(label, val, lc=YE, vc=WH, w=20):
    print(f"  {c(lc,B)}{label:<{w}}{c(r())}  {c(vc)}{val}{c(r())}")

def note(text, col=D):
    for line in fill(text, W-6).splitlines():
        print(f"  {c(col)}{line}{c(r())}")

def raw(text, col=CY, indent=4):
    pad = ' ' * indent
    for ln in text.splitlines():
        print(f"{pad}{c(col)}{ln}{c(r())}")

# ── helpers ───────────────────────────────────────────────────────────────────
def sg(d, *keys, default='—'):
    for k in keys:
        if not isinstance(d, dict): return default
        d = d.get(k)
        if d is None: return default
    return d if d != {} else default

def ts(s):
    if not s or s == '—': return '—'
    try: return datetime.fromisoformat(s.replace('Z','+00:00')).strftime('%Y-%m-%d %H:%M:%S Z')
    except: return s

def fsize(v):
    try: n = int(v); return f"{n:,} B  ({n//1024} KB)"
    except: return str(v) if v else '—'

# ── git repo sync ─────────────────────────────────────────────────────────────
def sync_repo(no_pull=False):
    git_dir = os.path.join(REPO_PATH, '.git')
    if not os.path.isdir(git_dir):
        print(f"  {c(CY)}[repo]{c(r())} cloning elastic/protections-artifacts (first run, ~50 MB)...")
        try:
            r2 = subprocess.run(['git','clone','--depth=1', REPO_URL, REPO_PATH],
                                capture_output=True, text=True, timeout=120)
            if r2.returncode == 0: print(f"  {c(GR)}cloned ok{c(r())}")
            else: print(f"  {c(YE)}clone failed: {r2.stderr.strip()[:120]}{c(r())}")
        except FileNotFoundError:
            print(f"  {c(YE)}git not found in PATH{c(r())}")
        except Exception as e:
            print(f"  {c(YE)}{e}{c(r())}")
    elif not no_pull:
        r2 = subprocess.run(['git','-C', REPO_PATH,'pull','--ff-only','--quiet'],
                            capture_output=True, text=True, timeout=60)
        msg = r2.stdout.strip() or 'already up to date'
        print(f"  {c(CY)}[repo]{c(r())} {msg}")

# ── local TOML lookup ─────────────────────────────────────────────────────────
def find_toml(rule_id):
    if not rule_id: return None, None, None
    rules_dir = os.path.join(REPO_PATH, 'behavior', 'rules')
    if not os.path.isdir(rules_dir): return None, None, None
    for dp, _, fnames in os.walk(rules_dir):
        for fn in fnames:
            if not fn.endswith('.toml'): continue
            fp = os.path.join(dp, fn)
            try:
                txt = open(fp, encoding='utf-8', errors='replace').read()
                if rule_id not in txt: continue
                return _toml_load(fp), fp, txt
            except: continue
    return None, None, None

def _re_str(content, key):
    m = re.search(rf'^{key}\s*=\s*"(.+?)"', content, re.M)
    return m.group(1) if m else None

def _re_block(content, key):
    m = re.search(rf'^{key}\s*=\s*"""(.+?)"""', content, re.M|re.S)
    return m.group(1).strip() if m else None

def _re_query(content):
    for q in [r"query\s*=\s*'''(.+?)'''", r'query\s*=\s*"""(.+?)"""', r'query\s*=\s*"(.+?)"']:
        m = re.search(q, content, re.M|re.S)
        if m: return m.group(1).strip()
    return None

def _re_list(content, key):
    m = re.search(rf'^{key}\s*=\s*\[(.+?)\]', content, re.S)
    return re.findall(r'"([^"]+)"', m.group(1)) if m else []

def parse_toml_meta(parsed, content):
    if parsed:
        rule = parsed.get('rule', {})
        threats = parsed.get('threat', [])
        techs, tactics = [], []
        for t in threats:
            tac = t.get('tactic', {})
            if tac.get('name'): tactics.append(tac['name'])
            for tech in t.get('technique', []):
                techs.append({'id': tech.get('id',''), 'name': tech.get('name',''),
                              'ref': tech.get('reference','')})
                for s in tech.get('subtechnique', []):
                    techs.append({'id': s.get('id',''), 'name': s.get('name',''),
                                  'ref': s.get('reference','')})
        acts = [a.get('action','') for a in parsed.get('actions',[]) + parsed.get('optional_actions',[])]
        return {
            'id': rule.get('id',''), 'name': rule.get('name',''),
            'description': rule.get('description',''),
            'os_list': rule.get('os_list',[]), 'version': rule.get('version',''),
            'query': rule.get('query',''), 'references': rule.get('reference',[]),
            'min_ep': rule.get('min_endpoint_version',''),
            'techniques': techs, 'tactics': tactics, 'actions': list(set(acts)),
        }
    else:
        techs = [{'id':t,'name':'','ref':''} for t in re.findall(r'id\s*=\s*"(T\d{4}(?:\.\d{3})?)"', content)]
        return {
            'id': _re_str(content,'id') or '',
            'name': _re_str(content,'name') or '',
            'description': _re_block(content,'description') or _re_str(content,'description') or '',
            'os_list': _re_list(content,'os_list'),
            'version': _re_str(content,'version') or '',
            'query': _re_query(content) or '',
            'references': _re_list(content,'reference'),
            'min_ep': _re_str(content,'min_endpoint_version') or '',
            'techniques': techs, 'tactics': [],
            'actions': list(set(re.findall(r'action\s*=\s*"([^"]+)"', content))),
        }

# ── EQL condition evaluator ───────────────────────────────────────────────────
def explain_eql(query, src, toml_meta):
    """
    Walk the EQL query condition-by-condition and show which matched.
    Returns list of dicts: {status, condition, evidence, detail}
    status: 'match' | 'skip' | 'gun' | 'miss'
    """
    proc  = src.get('process', {}) or {}
    dll   = src.get('dll', {}) or {}
    f_dat = src.get('file', {}) or {}
    thread_ext = sg(proc, 'thread', 'Ext', default={}) or {}
    stack = thread_ext.get('call_stack', []) if isinstance(thread_ext, dict) else []
    summary = thread_ext.get('call_stack_summary', '') if isinstance(thread_ext, dict) else ''
    results = []

    # ── parse query into logical conditions ───────────────────────────────────
    # Strip the event type prefix (e.g. "library where", "process where", etc.)
    body = re.sub(r'^\s*\w+\s+where\s+', '', query.strip())

    # Split on 'and' boundaries at the top level (not inside _arraysearch blocks)
    # Simple approach: split on ' and\n' or ' and ' that aren't inside ()
    conditions = _split_eql_conditions(body)

    for cond in conditions:
        cond = cond.strip()
        if not cond: continue
        is_not = cond.startswith('not ')
        inner  = cond[4:].strip() if is_not else cond

        ev = _eval_condition(inner, proc, dll, f_dat, stack, summary)
        if ev is None:
            # can't evaluate — just show the condition
            results.append({'status': 'check', 'condition': cond, 'evidence': '', 'detail': ''})
            continue

        matched, evidence, detail = ev

        if is_not:
            # exclusion: if matched = excluded → would have been a miss
            if matched:
                status = 'miss'  # exclusion applied — should not have fired
            else:
                status = 'skip'  # exclusion didn't apply — this is why it still fired
        else:
            status = 'match' if matched else 'miss'

        results.append({'status': status, 'condition': cond,
                        'evidence': evidence, 'detail': detail})

    # find smoking guns: private allocation frames
    for i, frame in enumerate(stack):
        if not isinstance(frame, dict): continue
        priv = frame.get('allocation_private_bytes', 0)
        if not priv: continue
        wl = ('ntdll.dll', 'kernelbase.dll', 'wininet.dll', 'ws2_32.dll', 'Unbacked')
        sym = frame.get('symbol_info', '?')
        if not any(w in sym for w in wl):
            trail = frame.get('callsite_trailing_bytes', '')
            results.append({'status': 'gun',
                            'condition': f'shellcode frame [{i:02d}]',
                            'evidence':  f'{sym}  [{priv:,} B private]',
                            'detail':    f'trailing: {trail[:60]}...' if trail else ''})
    return results

def _split_eql_conditions(body):
    """Split EQL body on 'and' at depth 0 (not inside parentheses/brackets)."""
    parts, buf, depth = [], [], 0
    tokens = re.split(r'(\band\b|\(|\))', body)
    for tok in tokens:
        if tok == '(': depth += 1; buf.append(tok)
        elif tok == ')': depth -= 1; buf.append(tok)
        elif tok == 'and' and depth == 0:
            parts.append(''.join(buf).strip()); buf = []
        else:
            buf.append(tok)
    if buf: parts.append(''.join(buf).strip())
    return [p for p in parts if p]

def _eval_condition(cond, proc, dll, f_dat, stack, summary):
    """
    Try to evaluate a single EQL condition against alert data.
    Returns (matched: bool, evidence: str, detail: str) or None if unable.
    """
    # dll.code_signature.subject_name == "value"
    m = re.match(r'dll\.code_signature\.subject_name\s*==\s*"(.+?)"', cond)
    if m:
        expected = m.group(1)
        actual   = sg(dll, 'code_signature', 'subject_name')
        matched  = (actual == expected)
        return matched, f'dll={sg(dll,"name")}  signed_by="{actual}"', ''

    # process.thread.Ext.call_stack_summary regex "..."
    m = re.match(r'process\.thread\.Ext\.call_stack_summary\s+regex\s+"""(.+?)"""', cond, re.S)
    if m:
        pattern = m.group(1).strip()
        matched = bool(re.search(pattern, summary))
        return matched, f'summary="{summary}"', f'pattern: {pattern}'

    # process.thread.Ext.call_stack_summary like "..."
    m = re.match(r'process\.thread\.Ext\.call_stack_summary\s+like\s+"(.+?)"', cond)
    if m:
        pattern = m.group(1).replace('*','.*')
        matched = bool(re.search(pattern, summary, re.I))
        return matched, f'summary="{summary}"', ''

    # _arraysearch(process.thread.Ext.call_stack, ...) with symbol_info wildcard
    m = re.search(r'\$entry\.symbol_info\s*:\s*\((.+?)\)', cond, re.S)
    if m and '_arraysearch' in cond and 'call_stack' in cond:
        patterns = [p.strip().strip('"').replace('*','.*') for p in m.group(1).split(',')]
        found = None
        for frame in stack:
            if not isinstance(frame, dict): continue
            sym = frame.get('symbol_info', '')
            if any(re.match(p, sym, re.I) for p in patterns):
                found = sym; break
        return bool(found), f'frame: {found}' if found else 'no matching frame', ''

    # process.name : ("a", "b") or process.name in (...)
    m = re.match(r'process\.name\s*(?:in\s*\(|:\s*\()(.+?)\)', cond, re.S)
    if m:
        names = re.findall(r'"([^"]+)"', m.group(1))
        pname = sg(proc, 'name', default='')
        matched = pname.lower() in [n.lower() for n in names]
        return matched, f'process.name="{pname}"', f'list: {", ".join(names[:4])}'

    # dll.name in (...) or dll.name : "..."
    m = re.match(r'dll\.name\s*(?:in\s*\(|:\s*"?)(.+?)(?:\)|")', cond)
    if m:
        names = re.findall(r'"([^"]+)"', m.group(0))
        dname = sg(dll, 'name', default='')
        matched = dname.lower() in [n.lower() for n in names]
        return matched, f'dll.name="{dname}"', f'excluded: {", ".join(names)}'

    # process.name : ("msedge.exe", ...) combined check
    m = re.search(r'process\.name\s*:\s*\((.+?)\)', cond)
    if m:
        names = re.findall(r'"([^"]+)"', m.group(1))
        pname = sg(proc, 'name', default='')
        matched = pname.lower() in [n.lower() for n in names]
        return matched, f'process.name="{pname}"', ''

    # dll.name : "FWPUCLNT.DLL" ...
    m = re.match(r'dll\.name\s*:\s*"(.+?)"', cond)
    if m:
        expected = m.group(1)
        actual   = sg(dll, 'name', default='')
        return actual.lower() == expected.lower(), f'dll.name="{actual}"', ''

    return None  # unknown condition shape

# ── ML detection explainer ────────────────────────────────────────────────────
def explain_ml(file_data, proc):
    """Return list of (label, value, note) for what contributed to ML score."""
    lines = []
    ml = sg(file_data, 'Ext', 'malware_classification', default={}) or {}
    if not ml: return lines

    score = ml.get('score', 0)
    thr   = ml.get('threshold', 0.58)
    ratio = score / thr if thr else 0
    lines.append(('model',     ml.get('identifier','?'), f'v{ml.get("version","?")}'))
    lines.append(('score',     f'{score:.4f}',
                  f'threshold {thr}  →  {ratio:.1f}x over  ({score*100:.1f}% confidence)'))

    # Observable PE properties that influence score
    sig_exists = sg(file_data, 'code_signature', 'exists')
    if sig_exists is False or sig_exists == False:
        lines.append(('unsigned',   'no code signature',
                      'strong ML indicator — most malware is unsigned'))

    tmp = sg(file_data, 'Ext', 'temp_file_path')
    if tmp and tmp != '—':
        lines.append(('staging',    'TEMP → target path',
                      f'{tmp}  →  {sg(file_data,"path")}'))

    path = sg(file_data, 'path', default='')
    for pat, why in [
        (r'\\ProgramData\\', 'C:\\ProgramData is a common loader drop zone'),
        (r'\\AppData\\Roaming\\', 'AppData\\Roaming used to avoid UAC path checks'),
        (r'\\Windows\\Temp\\', 'Win Temp as staging — noisy pattern'),
        (r'\\Users\\Public\\', 'Public folder — world-writable, common in scripts'),
    ]:
        if re.search(pat, path, re.I):
            lines.append(('drop_path', path, why)); break

    size = sg(file_data, 'size', default=None)
    if size:
        try: lines.append(('file_size', fsize(size), ''))
        except: pass

    cmd = sg(proc, 'command_line', default='')
    if '/nousecheck' in cmd.lower():
        lines.append(('parent_arg', '/NoUACCheck on explorer.exe', 'UAC bypass via Explorer'))
    parent_cmd = sg(proc.get('parent',{}), 'command_line', default='')
    if 'schedule' in parent_cmd.lower():
        lines.append(('spawner', 'svchost -s Schedule', 'Task Scheduler spawned the dropper'))

    return lines

# ── process chain renderer ────────────────────────────────────────────────────
def render_chain(proc, dll_data, file_data):
    parent = proc.get('parent', {}) or {}
    ppid   = sg(parent, 'pid')
    pname  = sg(parent, 'name')
    pcmd   = sg(parent, 'command_line')
    pid    = sg(proc, 'pid')
    pname2 = sg(proc, 'name')
    cmd2   = sg(proc, 'command_line')
    sha2   = sg(proc, 'hash', 'sha256')
    signed = sg(proc, 'code_signature', 'exists')
    imp    = sg(proc, 'pe', 'imphash', default='')

    # parent unbacked flag
    punbacked = sg(parent, 'thread', 'Ext', 'call_stack_contains_unbacked', default=False)

    lines = []
    if pname and pname != '—':
        inj_tag = f"  {c(RE,B)}[injected]{c(r())}" if punbacked else ''
        lines.append(f"  {c(YE,B)}({ppid}) {pname}{c(r())}{inj_tag}")
        if pcmd and pcmd != '—':
            lines.append(f"  {c(D)}  cmd: {pcmd}{c(r())}")
        lines.append(f"  {c(D)}  └─ spawned{c(r())}")

    sig_str = (f"{c(RE)}unsigned{c(r())}" if signed is False
               else f"{c(GR)}{sg(proc,'code_signature','subject_name')}{c(r())}")
    lines.append(f"  {c(OR,B)}({pid}) {pname2}{c(r())}  sig:{sig_str}")
    if cmd2 and cmd2 != '—':
        lines.append(f"  {c(D)}  cmd: {cmd2}{c(r())}")
    if sha2 and sha2 != '—':
        lines.append(f"  {c(D)}  sha256: {sha2}{c(r())}")
    if imp:
        lines.append(f"  {c(D)}  imphash: {imp}{c(r())}")

    if dll_data and sg(dll_data, 'path') != '—':
        lines.append(f"  {c(D)}  └─ loaded dll (stomped){c(r())}")
        dll_sig = sg(dll_data, 'code_signature', 'subject_name')
        dll_sha = sg(dll_data, 'hash', 'sha256')
        lines.append(f"  {c(MA)}  {sg(dll_data,'path')}{c(r())}  [{c(GR)}{dll_sig}{c(r())}]")
        if dll_sha and dll_sha != '—':
            lines.append(f"  {c(D)}  sha256: {dll_sha}{c(r())}")

    if file_data and sg(file_data, 'path') != '—':
        lines.append(f"  {c(D)}  └─ dropped{c(r())}")
        f_sig = sg(file_data, 'code_signature', 'exists')
        sig_tag = f"  {c(RE)}[unsigned]{c(r())}" if f_sig is False else ''
        lines.append(f"  {c(RE,B)}  {sg(file_data,'path')}{c(r())}{sig_tag}")

    for ln in lines: print(ln)

# ── main ──────────────────────────────────────────────────────────────────────
def analyze(data, no_pull=False):
    src = data.get('_source', data)

    # pull key fields
    event_obj  = src.get('event', {}) or {}
    event_code = event_obj.get('code', '') if isinstance(event_obj, dict) else ''
    event_types= event_obj.get('type', []) if isinstance(event_obj, dict) else []
    sev        = sg(src, 'kibana.alert.severity', default='')
    risk       = sg(src, 'kibana.alert.risk_score', default='')
    timestamp  = sg(src, '@timestamp')
    host       = src.get('host', {}) or {}
    proc       = src.get('process', {}) or {}
    file_data  = src.get('file', {}) or {}
    dll_data   = src.get('dll', {}) or {}
    user_data  = src.get('user', {}) or {}
    responses  = src.get('Responses', []) or []
    agent_info = src.get('agent', {}) or {}
    ep_rule    = src.get('rule', {}) or {}

    ep_rule_id   = ep_rule.get('id', '')
    ep_rule_name = ep_rule.get('name', '')
    ep_rule_desc = ep_rule.get('description', '')
    ep_ruleset   = ep_rule.get('ruleset', '')
    ep_rule_ver  = ep_rule.get('version', '')

    blocked = 'denied' in event_types or bool(responses)

    # ── sync repo + lookup ────────────────────────────────────────────────────
    print()
    sync_repo(no_pull)
    toml_meta, toml_path = None, None
    if ep_rule_id:
        parsed, toml_path, content = find_toml(ep_rule_id)
        if toml_path:
            toml_meta = parse_toml_meta(parsed, content)
            rel = os.path.relpath(toml_path, REPO_PATH)
            print(f"  {c(GR)}[rule] {rel}{c(r())}")
        else:
            print(f"  {c(YE)}[rule] {ep_rule_id[:8]}... not found locally — git pull may help{c(r())}")

    # ── header ────────────────────────────────────────────────────────────────
    sev_tag = {'high': SEV_H, 'critical': SEV_C, 'medium': SEV_M}.get(sev.lower(), SEV_M)
    act_tag = BLOCKED() if blocked else DETECTED()

    print()
    print(f"  {act_tag}  {sev_tag()}  {c(B)}{event_code or '?'}{c(r())}")
    print(f"  {c(D)}{ts(timestamp)}{c(r())}  │  {c(WH)}{sg(host,'hostname')}.{sg(host,'domain')}{c(r())}  │  "
          f"{c(WH)}{sg(user_data,'domain')}\\{sg(user_data,'name')}{c(r())}")

    # ── detection rule ────────────────────────────────────────────────────────
    div('DETECTION RULE')
    if ep_rule_id:
        rule_display = toml_meta['name'] if toml_meta else ep_rule_name
        kv('rule',    rule_display, vc=MA)
        kv('rule_id', ep_rule_id, vc=D)
        if toml_meta:
            kv('source', f"protections-artifacts/{os.path.relpath(toml_path, REPO_PATH)}", vc=D)
            kv('os',     ', '.join(toml_meta.get('os_list', [])), vc=WH)
            kv('min_ep', toml_meta.get('min_ep',''), vc=D)
            kv('ver',    toml_meta.get('version',''), vc=D)
        else:
            kv('name',    ep_rule_name, vc=MA)
            kv('desc',    ep_rule_desc, vc=WH)
            kv('ruleset', ep_ruleset, vc=D)
    else:
        # ML / malware — no specific behavior rule
        kv('engine', 'endpointpe-v4-model  (ML PE classifier)', vc=MA)
        ml = sg(file_data, 'Ext', 'malware_classification', default={}) or {}
        kv('model_ver', ml.get('version',''), vc=D)

    # ── why it fired ──────────────────────────────────────────────────────────
    div('WHY IT FIRED')

    if event_code == 'behavior' and toml_meta and toml_meta.get('query'):
        query = toml_meta['query']

        # show the EQL first
        print(f"\n  {c(D)}EQL query:{c(r())}")
        raw(query, col=CY, indent=4)
        print()

        results = explain_eql(query, src, toml_meta)

        for res in results:
            status = res['status']
            cond   = res['condition']
            evid   = res['evidence']
            detail = res['detail']

            if status == 'gun':
                tag = SMOKEGUN()
                col = RE
            elif status == 'match':
                tag = MATCHED()
                col = WH
            elif status == 'skip':
                tag = SKIPD()
                col = D
            elif status == 'miss':
                # exclusion that fired — this would stop detection
                tag = _status('EXCL', '42', WH)
                col = D
            else:
                tag = f"  {c(D)}[?]{c(r())}"
                col = D

            print(f"  {tag}  {c(col)}{cond}{c(r())}")
            if evid:  print(f"  {c(D)}       {evid}{c(r())}")
            if detail: print(f"  {c(D)}       {detail}{c(r())}")
            print()

    elif event_code == 'malicious_file':
        ml_lines = explain_ml(file_data, proc)
        for label, val, note_text in ml_lines:
            kv(label, val, lc=YE, vc=WH if 'score' in label or 'model' in label else RE if label in ('unsigned','staging') else WH)
            if note_text:
                print(f"  {c(D)}  └  {note_text}{c(r())}")
        print()
        # bar
        ml = sg(file_data, 'Ext', 'malware_classification', default={}) or {}
        score = ml.get('score', 0)
        thr   = ml.get('threshold', 0.58)
        n     = int(score * 40)
        t_pos = int(thr * 40)
        bar   = f"{'█'*n}{'░'*(40-n)}"
        print(f"    {c(RE)}[{bar}]{c(r())}  {score:.4f}")
        print(f"    {' '*(t_pos+1)}{c(YE)}^{thr:.2f}{c(r())}")

    else:
        # generic fallback
        kv('event_code', event_code)
        if ep_rule_desc: note(ep_rule_desc, D)

    # ── call stack summary (behavior only) ────────────────────────────────────
    thread_ext = sg(proc, 'thread', 'Ext', default={}) or {}
    summary    = thread_ext.get('call_stack_summary','') if isinstance(thread_ext,dict) else ''
    stack      = thread_ext.get('call_stack',[]) if isinstance(thread_ext,dict) else []

    if stack:
        div('CALL STACK')
        if summary:
            print(f"  {c(MA)}{summary}{c(r())}")
        print()
        for i, frame in enumerate(stack):
            if not isinstance(frame,dict): continue
            sym   = frame.get('symbol_info','?')
            priv  = frame.get('allocation_private_bytes', 0)
            trail = frame.get('callsite_trailing_bytes','')
            lead  = frame.get('callsite_leading_bytes','')

            if priv:
                print(f"  {c(RE,B)}[{i:02d}] {sym}  [{priv:,} B private alloc]{c(r())}")
                if lead:  print(f"  {c(D)}      lead:  {lead[:60]}...{c(r())}")
                if trail: print(f"  {c(D)}      trail: {trail[:60]}...{c(r())}")
            else:
                # annotate interesting frames
                ann = ''
                if 'NtMapViewOfSection' in sym: ann = f"  {c(D)}← section mapping{c(r())}"
                elif 'InternetOpen' in sym or 'HttpQuery' in sym: ann = f"  {c(YE)}← network{c(r())}"
                elif 'LdrGetDll' in sym or 'LdrLoad' in sym: ann = f"  {c(D)}← dll resolution{c(r())}"
                elif '.dll+0x' in sym and '!' not in sym: ann = f"  {c(YE)}← RVA only (no symbol){c(r())}"
                print(f"  {c(D)}[{i:02d}]{c(r())} {sym}{ann}")

    # ── process chain ─────────────────────────────────────────────────────────
    div('PROCESS CHAIN')
    render_chain(proc, dll_data if dll_data else {}, file_data)

    # ── hashes ────────────────────────────────────────────────────────────────
    div('HASHES')
    proc_sha  = sg(proc, 'hash', 'sha256')
    file_sha  = sg(file_data, 'hash', 'sha256')
    dll_sha   = sg(dll_data, 'hash', 'sha256')
    if proc_sha != '—':  kv(sg(proc,'name'), proc_sha, lc=D, vc=CY)
    if file_sha != '—':  kv(sg(file_data,'name'), file_sha, lc=D, vc=CY)
    if dll_sha  != '—':  kv(sg(dll_data,'name')  + ' [legit]', dll_sha, lc=D, vc=D)

    vt_hash = proc_sha if proc_sha != '—' else file_sha
    if vt_hash and vt_hash != '—':
        print(f"\n  {c(BL,D)}VT: https://www.virustotal.com/gui/file/{vt_hash}{c(r())}")

    # ── MITRE ─────────────────────────────────────────────────────────────────
    div('MITRE ATT&CK')
    seen = set()
    if toml_meta:
        for t in toml_meta.get('techniques', []):
            if t['id'] in seen: continue
            seen.add(t['id'])
            print(f"  {c(MA,B)}{t['id']:<12}{c(r())}  {t['name']}  {c(D)}{t.get('ref','')}{c(r())}")
    # inferred
    inferred = []
    if event_code == 'malicious_file':
        inferred += [('T1204.002','User Execution: Malicious File')]
    if any(f.get('allocation_private_bytes',0) for f in stack):
        inferred += [('T1620','Reflective Code Loading')]
    if dll_data:
        inferred += [('T1055.001','Process Injection: DLL Injection')]
    parent_cmd = sg(proc.get('parent',{}),'command_line',default='')
    if 'schedule' in parent_cmd.lower():
        inferred += [('T1053.005','Scheduled Task')]
    if '/nousecheck' in (sg(proc,'command_line') or '').lower():
        inferred += [('T1548.002','Bypass UAC')]
    for tid, tname in inferred:
        if tid in seen: continue
        seen.add(tid)
        print(f"  {c(MA,B)}{tid:<12}{c(r())}  {tname}  {c(D)}[inferred]{c(r())}")

    # ── automated response ─────────────────────────────────────────────────────
    if responses:
        div('ELASTIC RESPONSE')
        for resp in responses:
            action = resp.get('action', {})
            act    = action.get('action', '?') if isinstance(action,dict) else str(action)
            result = resp.get('result', -1)
            tree   = action.get('tree', False) if isinstance(action,dict) else False
            pname  = sg(resp.get('process',{}),'name')
            ppid   = sg(resp.get('process',{}),'pid')
            ok_str = c(GR,'SUCCESS') if result == 0 else c(RE,'FAILED')
            tree_s = '  tree=true (entire process tree)' if tree else ''
            print(f"  {ok_str}{c(r())}  {c(B)}{act}{c(r())}  →  {pname} ({ppid}){c(D)}{tree_s}{c(r())}")

    # ── quarantine ────────────────────────────────────────────────────────────
    qr = sg(file_data, 'Ext', 'quarantine_result', default=None)
    if qr is True:
        div('QUARANTINE')
        qp = sg(file_data, 'Ext', 'quarantine_path')
        print(f"  {c(GR)}quarantined  →  {qp}{c(r())}")

    print()


def main():
    global COLOR
    args = sys.argv[1:]
    if '--no-color' in args: COLOR = False
    banner()
    if not args or '-h' in args or '--help' in args:
        print(__doc__); sys.exit(0)
    json_file = args[0]
    no_pull   = '--no-pull'   in args
    no_color  = '--no-color'  in args

    if not os.path.isfile(json_file):
        print(f"not found: {json_file}", file=sys.stderr); sys.exit(1)

    with open(json_file, encoding='utf-8') as f:
        try: data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"invalid json: {e}", file=sys.stderr); sys.exit(1)

    if isinstance(data, list):
        for i, item in enumerate(data):
            print(f"\n{'─'*W}  [{i+1}/{len(data)}]")
            analyze(item, no_pull=no_pull)
    else:
        analyze(data, no_pull=no_pull)

if __name__ == '__main__':
    main()
