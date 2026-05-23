#!/usr/bin/env python3
"""
lab_extractor_pretty.py
Versão com saída formatada e colorida do lab_extractor.
Aceita input via stdin (cole bytes hex ou payload ASCII) ou --file.

Uso:
  python3 bytes.py        # cola/cola o payload e dá EOF
  python3 bytes.py -f stream.raw
"""

import argparse, sys, re, base64, json
from textwrap import shorten

# ------------------ util / cores ------------------
CSI = "\x1b["
RESET = CSI + "0m"
BOLD = CSI + "1m"
DIM = CSI + "2m"
UNDER = CSI + "4m"

FG_RED = CSI + "31m"
FG_GREEN = CSI + "32m"
FG_YELLOW = CSI + "33m"
FG_BLUE = CSI + "34m"
FG_MAG = CSI + "35m"
FG_CYAN = CSI + "36m"
FG_WHITE = CSI + "37m"

def c(s, color=""):
    return f"{color}{s}{RESET}"

def header(text):
    print(c("─" * 72, FG_BLUE))
    print(c("  " + text, FG_BLUE + BOLD))
    print(c("─" * 72, FG_BLUE))

def kv(k, v, key_color=FG_CYAN, val_color=FG_WHITE):
    print(f"{c(k+':', key_color):<20} {c(str(v), val_color)}")

def highlight(s, color=FG_YELLOW):
    return c(s, color + BOLD)

# ------------------ parsing helpers (same logic) ------------------
def clean_hex(s: str) -> bytes:
    s = s.strip()
    hex_chars = re.sub(r'[^0-9a-fA-F]', '', s)
    # if looks like hex bytes
    if len(hex_chars) >= 8 and re.fullmatch(r'(?:[0-9a-fA-F]{2}\s*)+', s) or len(hex_chars) >= 0.6*len(s.replace(" ", "")):
        if len(hex_chars) % 2 != 0:
            hex_chars = '0' + hex_chars
        return bytes.fromhex(hex_chars)
    # else treat as raw ascii payload
    return s.encode('latin1')

def mac_to_str(b: bytes) -> str:
    return ':'.join(f"{x:02x}" for x in b)

def ip4_to_str(b: bytes) -> str:
    return '.'.join(str(x) for x in b)

def parse_ethernet(frame: bytes):
    if len(frame) < 14: return None
    dst = frame[0:6]; src = frame[6:12]; ethertype = int.from_bytes(frame[12:14],'big')
    return {'dst_mac': dst, 'src_mac': src, 'ethertype': ethertype, 'eth_len': 14}

def parse_ipv4(frame: bytes, off: int):
    if len(frame) < off + 20: return None
    vihl = frame[off]; version = vihl>>4; ihl = vihl & 0x0F
    ip_header_len = ihl*4
    total_len = int.from_bytes(frame[off+2:off+4],'big')
    proto = frame[off+9]; src = frame[off+12:off+16]; dst = frame[off+16:off+20]
    flags_frag = int.from_bytes(frame[off+6:off+8],'big')
    flags = (flags_frag>>13)&0x7; frag_offset = flags_frag & 0x1FFF
    ttl = frame[off+8]; checksum = int.from_bytes(frame[off+10:off+12],'big')
    return {'version':version,'ihl':ihl,'ip_header_len':ip_header_len,'total_len':total_len,
            'proto':proto,'src':src,'dst':dst,'flags':flags,'frag_offset':frag_offset,
            'ttl':ttl,'checksum':checksum}

def parse_tcp(frame: bytes, off: int):
    if len(frame) < off + 20: return None
    sport = int.from_bytes(frame[off:off+2],'big'); dport = int.from_bytes(frame[off+2:off+4],'big')
    seq = int.from_bytes(frame[off+4:off+8],'big'); ack = int.from_bytes(frame[off+8:off+12],'big')
    data_offset = (frame[off+12] >> 4) & 0x0F; tcp_header_len = data_offset*4
    flags = frame[off+13]; window = int.from_bytes(frame[off+14:off+16],'big')
    checksum = int.from_bytes(frame[off+16:off+18],'big'); urg = int.from_bytes(frame[off+18:off+20],'big')
    return {'sport':sport,'dport':dport,'seq':seq,'ack':ack,'tcp_header_len':tcp_header_len,'flags':flags,'window':window,'checksum':checksum,'urg':urg}

def parse_udp(frame: bytes, off: int):
    if len(frame) < off + 8: return None
    sport = int.from_bytes(frame[off:off+2],'big'); dport = int.from_bytes(frame[off+2:off+4],'big')
    length = int.from_bytes(frame[off+4:off+6],'big'); checksum = int.from_bytes(frame[off+6:off+8],'big')
    return {'sport':sport,'dport':dport,'length':length,'checksum':checksum}

# ------------------ HTTP helpers ------------------
def extract_http_headers_and_body(payload_bytes: bytes):
    try:
        text = payload_bytes.decode('latin1', errors='replace')
    except:
        text = ''
    sep = '\r\n\r\n'
    idx = text.find(sep)
    if idx < 0:
        sep = '\n\n'
        idx = text.find(sep)
    if idx >= 0:
        header_block = text[:idx]
        body = payload_bytes[idx + len(sep):]
    else:
        header_block = text
        body = b''
    headers = {}
    lines = header_block.splitlines()
    if lines:
        headers['_start_line'] = lines[0].strip()
        for line in lines[1:]:
            if ':' in line:
                k,v = line.split(':',1)
                headers[k.strip().lower()] = v.strip()
    return headers, body, idx if idx>=0 else None

def decode_basic_auth(value: str):
    parts = value.split()
    if len(parts) >= 2 and parts[0].lower() == 'basic':
        try:
            userpass = base64.b64decode(parts[1]).decode('latin1')
            if ':' in userpass:
                return userpass.split(':',1)
            return userpass, None
        except:
            return None, None
    return None, None

def search_credentials_in_body(body_bytes: bytes):
    text = body_bytes.decode('latin1', errors='ignore')
    creds = {}
    m = re.search(r'(?i)(?:username|user|login)=([^&\s]+)', text)
    if m: creds['username'] = re.sub(r'\+',' ', m.group(1))
    m = re.search(r'(?i)(?:password|pass|senha)=([^&\s]+)', text)
    if m: creds['password'] = re.sub(r'\+',' ', m.group(1))
    try:
        j = json.loads(text)
        if isinstance(j, dict):
            for k in ('username','user','login','email'):
                if k in j and 'username' not in creds:
                    creds['username'] = str(j[k])
            for k in ('password','pass','senha'):
                if k in j and 'password' not in creds:
                    creds['password'] = str(j[k])
    except:
        pass
    return creds

def search_keys(text_bytes: bytes = b''):
    text = text_bytes.decode('latin1', errors='ignore')
    found = []
    patterns = [
        r'(?i)\b(key|api[_-]?key|access[_-]?key|secret|token|auth[_-]?token|session|flag)\b[:=]\s*([A-Za-z0-9\-_\.=]+)',
        r'(?i)"(key|api_key|access_key|token|session|flag)"\s*:\s*"([^"]+)"',
        r'(?i)(?:key|token)[\s"\'=:\[]+([A-Za-z0-9\-_\.=]{8,})'
    ]
    for p in patterns:
        for m in re.finditer(p, text):
            found.append(m.group(0))
    return list(dict.fromkeys(found))

# ------------------ analysis flow ------------------
def analyze_bytes(blob: bytes):
    eth = parse_ethernet(blob)
    out = {'ethernet':None,'ipv4':None,'tcp':None,'udp':None,'payload':b''}

    if eth and eth['ethertype'] == 0x0800 and len(blob) >= 34:
        out['ethernet'] = {'src_mac':mac_to_str(eth['src_mac']),'dst_mac':mac_to_str(eth['dst_mac']),'ethertype':eth['ethertype']}
        ip = parse_ipv4(blob, eth['eth_len'])
        if ip:
            out['ipv4'] = {'src':ip4_to_str(ip['src']),'dst':ip4_to_str(ip['dst']),'ip_header_len':ip['ip_header_len'],'total_len':ip['total_len'],'proto':ip['proto'],'ttl':ip['ttl']}
            l4_off = eth['eth_len'] + ip['ip_header_len']
            if ip['proto'] == 6:
                tcp = parse_tcp(blob, l4_off)
                if tcp:
                    out['tcp'] = tcp
                    payload_offset = l4_off + tcp['tcp_header_len']
                    payload_len = ip['total_len'] - (ip['ip_header_len'] + tcp['tcp_header_len'])
                    if payload_len < 0: payload_len = 0
                    out['payload'] = blob[payload_offset: payload_offset + payload_len]
            elif ip['proto'] == 17:
                udp = parse_udp(blob, l4_off)
                if udp:
                    out['udp'] = udp
                    payload_offset = l4_off + 8
                    payload_len = udp['length'] - 8 if udp['length'] >= 8 else len(blob) - payload_offset
                    out['payload'] = blob[payload_offset: payload_offset + payload_len]
            else:
                out['payload'] = blob[l4_off:]
        else:
            out['payload'] = blob
    else:
        out['payload'] = blob

    # parse HTTP if possible
    headers, body, hdrsep = extract_http_headers_and_body(out['payload'])
    out['http_headers'] = headers
    out['http_body'] = body
    payload_text = out['payload'].decode('latin1', errors='ignore')

    # extract referer / ua
    referer = headers.get('referer') if headers else None
    ua = headers.get('user-agent') if headers else None
    if not referer:
        m = re.search(r'(?im)^referer:\s*(.+)$', payload_text, flags=re.MULTILINE)
        if m: referer = m.group(1).strip()
    if not ua:
        m = re.search(r'(?im)^user-agent:\s*(.+)$', payload_text, flags=re.MULTILINE)
        if m: ua = m.group(1).strip()
    out['referer'] = referer
    out['user_agent'] = ua

    # Authorization basic
    auth = headers.get('authorization') if headers else None
    basic_user = basic_pass = None
    if auth:
        try:
            parts = auth.split()
            if len(parts) >= 2 and parts[0].lower() == 'basic':
                up = base64.b64decode(parts[1]).decode('latin1')
                if ':' in up:
                    basic_user, basic_pass = up.split(':',1)
                else:
                    basic_user = up
        except:
            pass
    if not auth:
        m = re.search(r'(?im)^authorization:\s*(.+)$', payload_text, flags=re.MULTILINE)
        if m:
            auth = m.group(1).strip()
            try:
                parts = auth.split()
                if len(parts) >= 2 and parts[0].lower() == 'basic':
                    up = base64.b64decode(parts[1]).decode('latin1')
                    if ':' in up:
                        basic_user, basic_pass = up.split(':',1)
                    else:
                        basic_user = up
            except:
                pass
    out['authorization'] = auth
    if basic_user:
        out['basic_user'] = basic_user; out['basic_pass'] = basic_pass

    # creds in body or payload
    creds = search_credentials_in_body(out['http_body'] if out['http_body'] else out['payload'])
    if creds: out['creds'] = creds

    # keys/tokens
    keys = search_keys(text_bytes=out['payload'])
    if keys: out['keys'] = keys

    # other headers
    extras = {}
    for h in ('host','cookie','authorization','referer','user-agent'):
        if headers and h in headers:
            extras[h] = headers[h]
        else:
            m = re.search(r'(?im)^' + re.escape(h) + r':\s*(.+)$', payload_text, flags=re.MULTILINE)
            if m: extras[h] = m.group(1).strip()
    out['other_headers'] = extras

    return out

# ------------------ pretty print results ------------------
def pretty_print(res):
    header("EXTRAÇÃO DO PACOTE")
    if res.get('ethernet'):
        e = res['ethernet']
        kv("Ethernet SRC", e['src_mac'])
        kv("Ethernet DST", e['dst_mac'])
        kv("EtherType", hex(e['ethertype']))
    if res.get('ipv4'):
        ip = res['ipv4']
        header("IPv4")
        kv("SRC IP", ip['src'])
        kv("DST IP", ip['dst'])
        kv("Total Length", ip['total_len'])
        kv("Header Len", ip['ip_header_len'])
        kv("Proto", ip['proto'])
        kv("TTL", ip['ttl'])
    if res.get('tcp'):
        t = res['tcp']
        header("TCP")
        kv("Src Port", t['sport'])
        kv("Dst Port", t['dport'])
        kv("Seq", t['seq'])
        kv("ACK", t['ack'])
        kv("TCP Header Len", t['tcp_header_len'])
        kv("Flags (hex)", f"0x{t['flags']:02x}")
        # show flag names
        names = []
        mapping = [("URG",0x20),("ACK",0x10),("PSH",0x08),("RST",0x04),("SYN",0x02),("FIN",0x01)]
        for n,mask in mapping:
            if t['flags'] & mask: names.append(n)
        kv("Flags set", ", ".join(names) if names else "None")
        kv("Window", t['window']); kv("Checksum", hex(t['checksum'])); kv("Urgent", t['urg'])
    if res.get('udp'):
        u = res['udp']
        header("UDP")
        kv("Src Port", u['sport']); kv("Dst Port", u['dport']); kv("Length", u['length']); kv("Checksum", hex(u['checksum']))

    # HTTP headers
    header("HTTP (extraído do payload)")
    headers = res.get('http_headers') or {}
    start = headers.get('_start_line', '')
    if start:
        print(c("Start-line: ", FG_MAG) + c(start, FG_WHITE))
    # show selected headers nicely
    important = ['host','referer','user-agent','authorization','cookie']
    for k in important:
        if k in headers:
            kv(k.capitalize(), headers[k])
    # other headers
    if res.get('other_headers'):
        extras = res['other_headers']
        for k,v in extras.items():
            if k not in headers and k in important:
                kv(k.capitalize(), v)

    # referer & ua explicit
    header("RESULTADOS PRINCIPAIS")
    kv("Referer", res.get('referer') or c("N/A", FG_YELLOW))
    kv("User-Agent", shorten(res.get('user_agent') or "N/A", 120))
    kv("Authorization (raw)", res.get('authorization') or "N/A")
    if res.get('basic_user'):
        kv("Basic user", res.get('basic_user'))
        kv("Basic pass", res.get('basic_pass'))

    # creds & keys
    if res.get('creds'):
        header("Credenciais encontradas")
        for k,v in res['creds'].items():
            kv(k, v, key_color=FG_YELLOW, val_color=FG_GREEN)
    if res.get('keys'):
        header("Keys / Tokens (context snippets)")
        for k in res['keys']:
            print(c(" • ", FG_WHITE) + c(shorten(k, 160), FG_GREEN))

    # payload snippet
    header("Payload (ASCII snippet)")
    payload = res.get('payload', b'')
    if payload:
        try:
            txt = payload.decode('latin1', errors='ignore')
            snippet = txt[:1200]
            # highlight found things
            def mark(text, pat, color=FG_RED):
                return re.sub(pat, lambda m: c(m.group(0), color+BOLD), text, flags=re.I)
            # highlight urls, referer and keys
            if res.get('referer'):
                snippet = snippet.replace(res['referer'], c(res['referer'], FG_YELLOW+BOLD))
            if res.get('user_agent'):
                snippet = snippet.replace(res['user_agent'][:100], c(res['user_agent'][:100], FG_CYAN+BOLD))
            for k in (res.get('keys') or []):
                snippet = snippet.replace(k, c(k, FG_MAG+BOLD))
            print(snippet)
        except Exception:
            print(c("[binary payload]", FG_YELLOW))
    else:
        print(c("[sem payload detectado]", FG_YELLOW))

    print(c("─" * 72, FG_BLUE))

# ------------------ CLI ------------------
def main():
    parser = argparse.ArgumentParser(description="Pretty extractor")
    parser.add_argument('-f','--file', help='Arquivo com hex/ASCII')
    args = parser.parse_args()

    if args.file:
        raw = open(args.file,'rb').read().decode('utf-8', errors='ignore')
        blob = clean_hex(raw)
    else:
        print("Cole os bytes hex ou payload ASCII. Finalize com EOF (Ctrl+D/Ctrl+Z+Enter):")
        raw = sys.stdin.read()
        blob = clean_hex(raw)

    res = analyze_bytes(blob)
    pretty_print(res)

if __name__ == "__main__":
    main()
