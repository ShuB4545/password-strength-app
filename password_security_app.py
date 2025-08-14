# advanced_password_security_lab_expanded.py
"""
Advanced Password Security Lab (Extended Version)
Features added compared to original:
- More pattern checks (palindromes, repeated substrings, keyboard walks)
- Multiple hashing algorithm simulator (MD5, SHA1, SHA256, bcrypt if available)
- Passphrase generator (diceware-like and wordlist combos)
- Attack simulation scenarios table (online/offline/slow-hash/GPU)
- Entropy vs length chart + composition pie chart
- Save/load analysis history (session + CSV export)
- Multi-language basic UI (English, Hindi, Marathi)
- Dark theme + custom CSS + Streamlit layout improvements
- Clipboard copy, improved PDF export (more fields), and example unit-testable helpers

Run:
    pip install streamlit requests reportlab bcrypt==4.0.1
    streamlit run advanced_password_security_lab_expanded.py

Note: bcrypt is optional (wrapped in try/except). HIBP (HaveIBeenPwned) breach check uses network.
"""

import math
import hashlib
import requests
import io
import os
import random
import time
from collections import Counter
from typing import List, Tuple, Dict, Optional

import streamlit as st
import matplotlib.pyplot as plt
import pandas as pd

# Optional bcrypt - used only to simulate slow hashing rounds
try:
    import bcrypt
    HAS_BCRYPT = True
except Exception:
    HAS_BCRYPT = False

# ReportLab for PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.lib.units import inch

# ============= PAGE CONFIG & CSS =============
st.set_page_config(page_title="Advanced Password Security Lab — Extended", layout="wide", page_icon="🔐")

# Dark theme CSS tweak (Streamlit needs unsafe_allow_html)
CSS = """
<style>
    .reportview-container { background: #0f1720; color: #cbd5e1; }
    .stButton>button { border-radius: 8px; }
    .stDownloadButton>button { background-color: #1f2937; color: #fff; }
    .big-title { font-size: 28px; font-weight: 700; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# ============= CONSTANTS & DICTs =============
CHARSETS = {
    "Lowercase (a-z)": 26,
    "Uppercase (A-Z)": 26,
    "Digits (0-9)": 10,
    "Symbols (!@#...)": 32,
    "All printable ASCII": 95,
}

WEAK_PASSWORDS = {
    "123456","password","12345678","qwerty","abc123",
    "111111","123123","password1","iloveyou","admin",
}

KEYBOARD_ROWS = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm"
]

DEFAULT_DICT_SAMPLE = [
    "password","qwerty","dragon","iloveyou","monkey","letmein",
    "football","admin","welcome","login","sunshine","princess"
]

# Diceware-like small wordlist for passphrase generator (expandable)
DICEWARE_SAMPLE = [
    "alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel",
    "india","juliet","kilo","lima","mike","november","oscar","papa",
]

# Leet map for deleet function
LEET_MAP = {
    "a":"4@","e":"3","i":"1!","o":"0","s":"$5","t":"7","+":"t"
}

# ============= HELPERS =============

def log2(x: float) -> float:
    return math.log(x, 2)


def pretty_time(seconds: float) -> str:
    if seconds is None or seconds != seconds:
        return "n/a"
    if seconds == float("inf") or seconds > 1e300:
        return "practically infinite"
    if seconds < 1e-6:
        return "≈ 0 sec"
    s = int(seconds)
    units = [
        ("year", 365 * 24 * 3600),
        ("day", 24 * 3600),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]
    parts = []
    for name, val in units:
        if s >= val:
            qty = s // val
            s -= qty * val
            parts.append(f"{qty} {name}{'s' if qty != 1 else ''}")
    return ", ".join(parts) if parts else "0 seconds"


def detect_charset_size(password: str) -> Tuple[int, Dict[str, bool]]:
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    size = 0
    if has_lower:  size += CHARSETS["Lowercase (a-z)"]
    if has_upper:  size += CHARSETS["Uppercase (A-Z)"]
    if has_digit:  size += CHARSETS["Digits (0-9)"]
    if has_symbol: size += CHARSETS["Symbols (!@#...)"]
    if size == 0:
        size = CHARSETS["All printable ASCII"]
    flags = {"lower": has_lower, "upper": has_upper, "digit": has_digit, "symbol": has_symbol}
    return size ** len(password), size, flags


def keyspace_by_length(length: int, selected_sets: List[str]) -> Tuple[int, int]:
    size = sum(CHARSETS[n] for n in selected_sets) if selected_sets else 0
    if size == 0:
        size = CHARSETS["All printable ASCII"]
    return size ** length, size


def shannon_entropy_bits(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    H = 0.0
    for c in counts.values():
        p = c / n
        H -= p * math.log(p, 2)
    return H * n


def find_sequences(password: str, min_len: int = 3) -> List[str]:
    findings = []
    p = password.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    digits   = "0123456789"
    universes = [alphabet, digits] + KEYBOARD_ROWS
    for universe in universes:
        for i in range(len(universe) - min_len + 1):
            seq = universe[i:i+min_len]
            if seq in p:
                findings.append(seq)
        rev = universe[::-1]
        for i in range(len(rev) - min_len + 1):
            seq = rev[i:i+min_len]
            if seq in p:
                findings.append(seq)
    return list(set(findings))


def looks_like_year(password: str) -> Optional[str]:
    for i in range(len(password) - 3):
        chunk = password[i:i+4]
        if chunk.isdigit():
            year = int(chunk)
            if 1900 <= year <= 2099:
                return chunk
    return None


def repeated_runs(password: str, min_run: int = 3) -> Optional[str]:
    if not password:
        return None
    run_char = password[0]
    run_len = 1
    for c in password[1:]:
        if c == run_char:
            run_len += 1
            if run_len >= min_run:
                return run_char * run_len
        else:
            run_char = c
            run_len = 1
    return None


def deleet(s: str) -> str:
    out = s.lower()
    for plain, subs in LEET_MAP.items():
        for ch in subs:
            out = out.replace(ch, plain)
    return out


def is_palindrome(s: str) -> bool:
    filtered = ''.join(ch.lower() for ch in s if ch.isalnum())
    return filtered == filtered[::-1] and len(filtered) >= 3


def repeated_substring(s: str) -> Optional[str]:
    # detect if string is multiple repeats of a smaller substring
    n = len(s)
    for l in range(1, n//2 + 1):
        if n % l == 0:
            sub = s[:l]
            if sub * (n // l) == s:
                return sub
    return None


def keyboard_walks(password: str, min_len: int = 4) -> List[str]:
    p = password.lower()
    findings = []
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_len + 1):
            seq = row[i:i+min_len]
            if seq in p:
                findings.append(seq)
        rev = row[::-1]
        for i in range(len(rev) - min_len + 1):
            seq = rev[i:i+min_len]
            if seq in p:
                findings.append(seq)
    return list(set(findings))


def pattern_penalties(password: str) -> Tuple[int, List[str]]:
    penalties = 0
    notes = []
    seqs = find_sequences(password, 3)
    if seqs:
        penalties += 1 + min(3, len(seqs)//2)
        notes.append(f"Sequential patterns: {', '.join(seqs)}")
    yr = looks_like_year(password)
    if yr:
        penalties += 1
        notes.append(f"Year-like: {yr}")
    rep = repeated_runs(password, 3)
    if rep:
        penalties += 1
        notes.append(f"Repeated chars: '{rep}'")
    sub = repeated_substring(password)
    if sub:
        penalties += 1
        notes.append(f"Repeated substring: '{sub}'")
    pal = is_palindrome(password)
    if pal:
        penalties += 1
        notes.append("Password is palindrome-like")
    kw = keyboard_walks(password, 4)
    if kw:
        penalties += 1
        notes.append(f"Keyboard walk patterns: {', '.join(kw)}")
    dl = deleet(password)
    common_hits = [w for w in DEFAULT_DICT_SAMPLE if w in dl]
    if common_hits:
        penalties += 1
        notes.append(f"Common words after deleet: {', '.join(set(common_hits))}")
    return penalties, notes


def strength_score(password: str) -> Tuple[int, List[str]]:
    tips = []
    score = 0
    L = len(password)
    if L >= 8:  score += 2
    if L >= 12: score += 2
    if L >= 16: score += 1
    ks, cs, flags = detect_charset_size(password)
    score += int(flags["lower"]) + int(flags["upper"]) + int(flags["digit"]) + int(flags["symbol"]) 
    if password.lower() not in WEAK_PASSWORDS:
        score += 1
    p, notes = pattern_penalties(password)
    score -= p
    if L < 12: tips.append("Increase length to at least 12 characters (passphrases are great).")
    if not flags["lower"]:  tips.append("Add lowercase letters.")
    if not flags["upper"]:  tips.append("Add uppercase letters.")
    if not flags["digit"]:  tips.append("Include digits.")
    if not flags["symbol"]: tips.append("Include special characters (!@#...).")
    if notes: tips.extend(notes)
    if password.lower() in WEAK_PASSWORDS: tips.append("Avoid common or leaked passwords.")
    return max(0, min(10, score)), tips

# ============= HIBP (Pwned Passwords) =============
@st.cache_data(show_spinner=False, ttl=60*30)
def hibp_breach_count(password: str, timeout: float = 6.0) -> Optional[int]:
    if not password:
        return None
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true", "User-Agent": "AdvancedPasswordLab/1.0"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return None
        for line in r.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0] == suffix:
                return int(parts[1])
        return 0
    except Exception:
        return None

# ============= ATTACK MODELS =============

def estimate_bruteforce_time(keyspace_size: int, attempts_per_sec: float, average=True) -> float:
    trials = keyspace_size / 2 if average else keyspace_size
    return trials / max(attempts_per_sec, 1e-30)


def estimate_dictionary_time(password: str, dictionary: List[str], words_per_sec: float) -> Tuple[float, bool]:
    pw_lower = password.lower()
    dict_list = [w.strip().lower() for w in dictionary if w.strip()]
    dict_set = set(dict_list)
    if pw_lower in dict_set:
        try_index = dict_list.index(pw_lower) + 1
        return try_index / max(words_per_sec, 1e-30), True
    attempts = 0
    found = False
    for w in dict_set:
        attempts += 1
        if w == pw_lower:
            found = True
            break
        wc = w.capitalize()
        attempts += 1
        if wc == password:
            found = True
            break
        for dlen in (1,2,3):
            attempts += (10 ** dlen)
            if password.startswith(w) or password.startswith(wc):
                tail = password[len(w):] if password.startswith(w) else password[len(wc):]
                if tail.isdigit() and 1 <= len(tail) <= dlen:
                    found = True
                    break
        if found:
            break
    secs = attempts / max(words_per_sec, 1e-30)
    return secs, found


def estimate_hybrid_time(password: str, dictionary: List[str], attempts_per_sec: float) -> float:
    penalties, _ = pattern_penalties(password)
    ks, _, _ = detect_charset_size(password)
    # safe-guard for huge ks
    if ks <= 0:
        ks = 1
    if penalties >= 3:
        eff = ks ** 0.5
    elif penalties == 2:
        eff = ks ** 0.7
    else:
        eff = ks ** 0.9
    trials = eff / 2
    return trials / max(attempts_per_sec, 1e-30)

# ============= HASHING SIMULATOR =============

def hash_simulation(password: str, algo: str = "sha256", bcrypt_rounds: int = 12) -> Tuple[str, float]:
    # returns (hash_hex_or_repr, simulated_seconds)
    start = time.time()
    if algo.lower() == "md5":
        h = hashlib.md5(password.encode()).hexdigest()
        elapsed = time.time() - start
        return h, elapsed
    if algo.lower() == "sha1":
        h = hashlib.sha1(password.encode()).hexdigest()
        elapsed = time.time() - start
        return h, elapsed
    if algo.lower() == "sha256":
        h = hashlib.sha256(password.encode()).hexdigest()
        elapsed = time.time() - start
        return h, elapsed
    if algo.lower() == "bcrypt":
        if not HAS_BCRYPT:
            return "bcrypt-not-installed", 0.0
        # simulate hashing time empirically by performing one bcrypt operation
        start2 = time.time()
        salt = bcrypt.gensalt(rounds=bcrypt_rounds)
        bh = bcrypt.hashpw(password.encode(), salt)
        elapsed = time.time() - start2
        return bh.decode() if isinstance(bh, bytes) else str(bh), elapsed
    return hashlib.sha256(password.encode()).hexdigest(), time.time() - start

# ============= PASS-PHRASE GENERATOR =============

def generate_passphrase(num_words: int = 4, separator: str = " ", wordlist: Optional[List[str]] = None) -> str:
    wl = wordlist or DICEWARE_SAMPLE
    words = [random.choice(wl) for _ in range(num_words)]
    return separator.join(words)

# ============= DICTIONARY LOADING =============
@st.cache_data(show_spinner=False)
def load_dictionary(file) -> List[str]:
    if file is None:
        return DEFAULT_DICT_SAMPLE
    try:
        content = file.read()
        try:
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            text = content.decode("latin-1", errors="ignore")
        words = [w.strip() for w in text.splitlines() if w.strip()]
        if len(words) > 500000:
            words = words[:500000]
        return words
    except Exception:
        return DEFAULT_DICT_SAMPLE

# ============= PDF Report =============

def make_pdf_report(pw: str,
                    language: str,
                    score: Optional[int],
                    ks: Optional[int],
                    charset_size: Optional[int],
                    Hk: Optional[float],
                    Hs: Optional[float],
                    breached: Optional[int],
                    bf_avg: Optional[float],
                    bf_worst: Optional[float],
                    dict_t: Optional[float],
                    dict_hit: Optional[bool],
                    hybrid_t: Optional[float],
                    hash_algo: Optional[str],
                    hash_time: Optional[float]) -> bytes:
    buffer = io.BytesIO()
    c = pdf_canvas.Canvas(buffer, pagesize=A4)
    w, h = A4
    x = inch * 0.6
    y = h - inch * 0.7

    def line(t, dy=14):
        nonlocal y
        c.drawString(x, y, t)
        y -= dy

    c.setFont("Helvetica-Bold", 16)
    line("Advanced Password Security Report (Extended)", 20)
    c.setFont("Helvetica", 10)

    display_pw = "(hidden)" if not pw else ("*" * min(8, len(pw))) + ("…" if len(pw) > 8 else "")
    line(f"Password (masked): {display_pw}")
    line(f"Language: {language}")
    line(f"Strength score: {score if score is not None else 'n/a'} / 10")
    line(f"Detected charset size: {charset_size if charset_size is not None else 'n/a'}")
    line(f"Keyspace: {format(ks, ',') if ks is not None else 'n/a'}")
    line(f"Keyspace entropy (bits): {Hk:.2f}" if Hk is not None else "Keyspace entropy: n/a")
    line(f"Shannon entropy (bits): {Hs:.2f}" if Hs is not None else "Shannon entropy: n/a")
    if breached is not None:
        if breached > 0:
            line(f"Breach check: FOUND {breached:,} times (HIBP)")
        else:
            line("Breach check: Not found in HIBP")
    else:
        line("Breach check: unavailable/offline")

    line("")
    line("Estimated crack times:")
    line(f"  • Brute-force (average): {pretty_time(bf_avg)}")
    line(f"  • Brute-force (worst):   {pretty_time(bf_worst)}")
    line(f"  • Dictionary:            {pretty_time(dict_t)} {'(likely hit)' if dict_hit else ''}")
    line(f"  • Hybrid (smart):        {pretty_time(hybrid_t)}")
    line("")
    line(f"Hash algorithm sample: {hash_algo} (sample time: {hash_time:.4f} sec)" if hash_algo else "Hash algorithm: n/a")
    line("")
    line("Notes:")
    line("  - Estimates depend on attacker speed & defenses (hashing/2FA/rate limits).")
    line("  - Use long, unique passphrases and a password manager.")

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()

# ============= SESSION HISTORY =============
if 'history' not in st.session_state:
    st.session_state.history = []  # list of dicts


def add_to_history(entry: Dict):
    # Keep recent 25
    st.session_state.history.insert(0, entry)
    st.session_state.history = st.session_state.history[:25]

# ============= UI =============
st.title("🔐 Advanced Password Security Lab — Extended")
st.caption("Educational tool: local analysis, HIBP uses k-anonymity for breach checks.")

with st.expander("What's new in the extended version?"):
    st.markdown("""
- Extra pattern detectors (palindromes, repeated substrings, keyboard walks)
- Hash algorithm simulator (bcrypt optional)
- Passphrase generator & copy button
- Attack scenarios + charts
- Multilanguage labels + session history
- PDF and CSV export for reports and history
""")

# Sidebar: settings + dictionary upload + language
with st.sidebar:
    st.header("⚙️ Settings & Tools")
    language = st.selectbox("Language / भाषा / भाषा निवडा", ["English", "हिंदी", "मराठी"], index=0)
    online_check = st.checkbox("Enable Breach Check (HIBP)", value=True)
    brute_speed = st.number_input("Brute-force attempts/sec (attacker)", value=1e9, step=1e7, format="%.0f")
    dict_speed  = st.number_input("Dictionary tries/sec", value=2e4, step=1e3, format="%.0f")
    hybrid_speed= st.number_input("Hybrid attempts/sec", value=5e7, step=1e6, format="%.0f")
    bcrypt_rounds = st.slider("bcrypt rounds (if available)", min_value=4, max_value=16, value=12)

    st.subheader("Load dictionary (optional)")
    dict_file = st.file_uploader("Upload wordlist (.txt)", type=["txt"], help="One word per line, e.g., rockyou.txt")
    st.write("\n")
    if HAS_BCRYPT:
        st.success("bcrypt library available")
    else:
        st.warning("bcrypt not installed — bcrypt simulation disabled (optional).")

# Load dictionary
dictionary = load_dictionary(dict_file)

# Main layout columns
col_left, col_right = st.columns((2,1))

with col_left:
    st.header("1) Analyze a Password")
    password = st.text_input("Enter a password (processed locally):", type="password")

    if password:
        # Score
        score, tips = strength_score(password)
        st.subheader(f"Strength: {score}/10")
        st.progress(score/10)

        # Entropies and keyspace
        ks_val, cs, flags = detect_charset_size(password)
        entropy_bits_keyspace = len(password) * (log2(cs) if cs>0 else 0)
        entropy_bits_shannon  = shannon_entropy_bits(password)

        st.write("**Entropy & Keyspace**")
        st.write(f"Charset size: `{cs}` — Keyspace: `{ks_val:,}`")
        st.write(f"Keyspace entropy: `{entropy_bits_keyspace:.2f}` bits — Shannon: `{entropy_bits_shannon:.2f}` bits")

        # Patterns
        p_penalty, p_notes = pattern_penalties(password)
        if p_notes:
            st.warning("Patterns found: " + "; ".join(p_notes))

        # HIBP
        breached_count = None
        if online_check:
            with st.spinner("Checking Have I Been Pwned (k-anonymity)…"):
                breached_count = hibp_breach_count(password)
        if breached_count is not None:
            if breached_count > 0:
                st.error(f"⚠ Found in known breaches {breached_count:,} times.")
            else:
                st.success("✅ Not found in HIBP dataset (still use unique passwords).")
        else:
            st.info("Breach check unavailable or offline.")

        # Attack estimates
        avg_brute_time  = estimate_bruteforce_time(ks_val, brute_speed, average=True)
        worst_brute_time= estimate_bruteforce_time(ks_val, brute_speed, average=False)
        dict_time, dict_found = estimate_dictionary_time(password, dictionary, dict_speed)
        hybrid_time = estimate_hybrid_time(password, dictionary, hybrid_speed)

        st.subheader("Estimated Crack Times")
        st.write(f"Brute-force (avg): {pretty_time(avg_brute_time)} — (worst: {pretty_time(worst_brute_time)})")
        st.write(f"Dictionary: {pretty_time(dict_time)} {'(likely hit ✅)' if dict_found else '(unlikely ❌)'}")
        st.write(f"Hybrid: {pretty_time(hybrid_time)}")

        # Hash sample
        st.subheader("Hashing simulator (sample)")
        hash_algo = st.selectbox("Hash algorithm to sample", ["sha256","sha1","md5","bcrypt"] if HAS_BCRYPT else ["sha256","sha1","md5"]) 
        hash_val, hash_time = hash_simulation(password, algo=hash_algo, bcrypt_rounds=bcrypt_rounds)
        st.write(f"Sample hash ({hash_algo}) — computation time: {hash_time:.4f} sec")
        st.code(hash_val[:120] + ("..." if len(str(hash_val))>120 else ""))

        # Suggestions
        st.subheader("Suggestions & Tips")
        if tips:
            for t in tips:
                st.write("- " + t)
        else:
            st.success("Password looks strong. Use long passphrases and a password manager.")

        # Add to history button
        if st.button("Save analysis to history"):
            entry = {
                'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'masked': ('*'*min(8,len(password))) + ('…' if len(password)>8 else ''),
                'score': score,
                'ks_entropy': round(entropy_bits_keyspace,2),
                'shannon': round(entropy_bits_shannon,2),
                'breached': breached_count if breached_count is not None else 'n/a'
            }
            add_to_history(entry)
            st.success('Saved to history')

    else:
        st.info("Type a password above to analyze it (keeps analysis local).")

    # -------- Passphrase generator --------
    st.header("2) Passphrase Generator")
    pg_col1, pg_col2 = st.columns([2,1])
    with pg_col1:
        num_words = st.slider("Words in passphrase", min_value=3, max_value=8, value=4)
        separator = st.selectbox("Separator", [" ", "-", "_"])
        use_wordlist = st.checkbox("Use uploaded dictionary as wordlist (if available)", value=False)
    with pg_col2:
        if st.button("Generate Passphrase"):
            wl = dictionary if use_wordlist and dictionary else DICEWARE_SAMPLE
            phrase = generate_passphrase(num_words=num_words, separator=separator, wordlist=wl)
            st.session_state.generated_passphrase = phrase
    if 'generated_passphrase' in st.session_state:
        st.text_input("Generated Passphrase", value=st.session_state.generated_passphrase, key='gen_pass', disabled=True)
        if st.button("Copy passphrase to clipboard"):
            st.write("(Use your browser/OS clipboard features — Streamlit can't directly place text in clipboard in all runtimes)")

with col_right:
    st.header("Quick Tools & Visuals")
    # ===== Charts: entropy vs length =====
    st.subheader("Entropy vs Length")
    selected_sets = st.multiselect("Character sets to include", list(CHARSETS.keys()), default=["Lowercase (a-z)", "Uppercase (A-Z)", "Digits (0-9)"])
    max_len = st.slider("Max length for chart", min_value=6, max_value=40, value=24)
    lengths = list(range(1, max_len+1))
    keyspace_times = []
    dict_vis = []
    hybrid_vis = []
    for L in lengths:
        ks_L, cs_L = keyspace_by_length(L, selected_sets)
        keyspace_times.append(estimate_bruteforce_time(ks_L, brute_speed, average=True))
        variants = min(len(dictionary) * max(1, L-4), 2_000_000)
        dict_vis.append(variants / max(dict_speed, 1e-30))
        eff = (ks_L ** 0.85)
        hybrid_vis.append((eff / 2) / max(hybrid_speed, 1e-30))

    fig1, ax1 = plt.subplots()
    ax1.plot(lengths, [max(1e-10,t) for t in keyspace_times], marker='o', label='Brute-force (avg)')
    ax1.plot(lengths, [max(1e-10,t) for t in dict_vis], marker='o', label='Dictionary')
    ax1.plot(lengths, [max(1e-10,t) for t in hybrid_vis], marker='o', label='Hybrid')
    ax1.set_yscale('log')
    ax1.set_xlabel('Length')
    ax1.set_ylabel('Estimated time (seconds, log)')
    ax1.legend()
    st.pyplot(fig1)

    # ===== Composition pie chart placeholder =====
    st.subheader("Password Composition (example)")
    sample = st.text_input("Enter sample for composition chart (optional)", key='comp_sample')
    if sample:
        counts = [sum(1 for c in sample if c.islower()), sum(1 for c in sample if c.isupper()), sum(1 for c in sample if c.isdigit()), sum(1 for c in sample if not c.isalnum())]
        labels = ['lower','upper','digits','symbols']
        fig2, ax2 = plt.subplots()
        ax2.pie(counts, labels=labels, autopct='%1.1f%%')
        ax2.set_title('Composition')
        st.pyplot(fig2)

    # ===== Attack Scenarios Table =====
    st.subheader("Attack scenarios")
    scenarios = [
        {'name':'Online guessing (10/sec)', 'speed':10},
        {'name':'Slow hash (100/sec)', 'speed':100},
        {'name':'Moderate GPU (1e7/sec)', 'speed':1e7},
        {'name':'High-end GPU (1e9/sec)', 'speed':1e9},
    ]
    if st.button('Show crack times for a sample passphrase'):
        sample_pw = st.session_state.get('gen_pass','Tr0ub4dor!')
        rows = []
        ks_s, cs_s, _ = detect_charset_size(sample_pw)
        for s in scenarios:
            t = estimate_bruteforce_time(ks_s, s['speed'], average=True)
            rows.append({'scenario': s['name'], 'time': pretty_time(t)})
        st.table(pd.DataFrame(rows))

# ===== History panel =====
st.header('History & Exports')
if st.session_state.history:
    df_hist = pd.DataFrame(st.session_state.history)
    st.dataframe(df_hist)
    csv = df_hist.to_csv(index=False).encode('utf-8')
    st.download_button('Download history (CSV)', data=csv, file_name='password_analysis_history.csv', mime='text/csv')
    if st.button('Clear history'):
        st.session_state.history = []
        st.experimental_rerun()
else:
    st.info('No history saved yet. Analyze a password and click "Save analysis to history".')

# ===== PDF Export for last analyzed password =====
st.header('Export Report')
if st.button('Generate PDF for last analysis'):
    if 'gen_pass' in st.session_state and st.session_state.gen_pass:
        pw = st.session_state.gen_pass
    elif 'last' in st.session_state and st.session_state.get('last'):
        pw = st.session_state.last
    else:
        pw = None
    if pw:
        score, _ = strength_score(pw)
        ks_val, cs, _ = detect_charset_size(pw)
        Hk = len(pw) * (log2(cs) if cs>0 else 0)
        Hs = shannon_entropy_bits(pw)
        breached = hibp_breach_count(pw) if online_check else None
        bf_avg  = estimate_bruteforce_time(ks_val, brute_speed, average=True)
        bf_worst= estimate_bruteforce_time(ks_val, brute_speed, average=False)
        dict_t, dict_hit = estimate_dictionary_time(pw, dictionary, dict_speed)
        hyb_t = estimate_hybrid_time(pw, dictionary, hybrid_speed)
        hash_val, hash_time = hash_simulation(pw, algo='sha256', bcrypt_rounds=bcrypt_rounds)
        pdf_bytes = make_pdf_report(pw, language, score, ks_val, cs, Hk, Hs, breached, bf_avg, bf_worst, dict_t, dict_hit, hyb_t, 'sha256', hash_time)
        st.download_button('Download PDF', data=pdf_bytes, file_name='password_report_extended.pdf', mime='application/pdf')
    else:
        st.warning('No passphrase available for PDF generation. Generate one or analyze a password first.')

# ===== Footer =====
st.caption('Educational demo — do not use this tool as an enterprise password auditor. Consider hashing policies, rate limiting, 2FA, and secure storage for production.')


# ---- Footer ----
st.markdown("---")
st.markdown("Made for education & college projects. Respect rate limits for HIBP (no API key required for range endpoint).")

