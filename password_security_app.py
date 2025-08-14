# password_security_app.py
# Advanced Password Security Lab (replacement file)
# Features:
# - Strength scoring with pattern detection
# - Shannon entropy + keyspace entropy
# - Breach check (HaveIBeenPwned k-anonymity)
# - Dictionary & hybrid attack estimators + multi-attack chart
# - Dictionary upload (e.g., rockyou.txt)
# - PDF report export (ReportLab)

import math
import hashlib
import requests
import io
from collections import Counter
from typing import List, Tuple, Dict, Optional

import streamlit as st
import matplotlib.pyplot as plt

# ============= CONFIG =============
st.set_page_config(
    page_title="Advanced Password Security Lab",
    layout="centered",
    page_icon="🔐"
)

# ======== CONSTANTS ========
CHARSETS = {
    "Lowercase (a-z)": 26,
    "Uppercase (A-Z)": 26,
    "Digits (0-9)": 10,
    "Symbols (!@#...)": 32,
    "All printable ASCII": 95,
}

# Tiny sample; real checks use HIBP & your dictionary file
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
    # small starter; upload rockyou.txt for serious checks
    "password","qwerty","dragon","iloveyou","monkey","letmein",
    "football","admin","welcome","login","sunshine","princess"
]

# Reasonable defaults (adjustable in sidebar)
DEFAULT_BRUTEFORCE_SPEED = 1e9        # attempts/sec (GPU cracking lab speed)
DEFAULT_DICT_SPEED       = 2e4        # words/sec (dictionary + mutations)
DEFAULT_HYBRID_SPEED     = 5e7        # attempts/sec (smart guesses + rules)

# ============= HELPERS =============
def log2(x: float) -> float:
    return math.log(x, 2)

def pretty_time(seconds: float) -> str:
    if seconds is None or seconds != seconds:  # NaN
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
    flags = {
        "lower": has_lower, "upper": has_upper,
        "digit": has_digit, "symbol": has_symbol
    }
    return size, flags

def keyspace(password: str) -> Tuple[int, int]:
    size, _ = detect_charset_size(password)
    return size ** len(password), size

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
    return H * n  # bits for the whole string

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

LEET_MAP = {
    "a":"4@","e":"3","i":"1!","o":"0","s":"$5","t":"7","+":"t"
}
def deleet(s: str) -> str:
    out = s.lower()
    for plain, subs in LEET_MAP.items():
        for ch in subs:
            out = out.replace(ch, plain)
    return out

def pattern_penalties(password: str) -> Tuple[int, List[str]]:
    penalties = 0
    notes = []
    seqs = find_sequences(password, 3)
    if seqs:
        penalties += 1 + min(2, len(seqs)//2)
        notes.append(f"Sequential patterns detected: {', '.join(seqs)}")
    yr = looks_like_year(password)
    if yr:
        penalties += 1
        notes.append(f"Contains year-like sequence: {yr}")
    rep = repeated_runs(password, 3)
    if rep:
        penalties += 1
        notes.append(f"Repeated characters: '{rep}'")
    dl = deleet(password)
    common_hits = [w for w in DEFAULT_DICT_SAMPLE if w in dl]
    if common_hits:
        penalties += 1
        notes.append(f"Looks like common word after de-leet: {', '.join(set(common_hits))}")
    return penalties, notes

def strength_score(password: str) -> Tuple[int, List[str]]:
    """
    Base score 0..10; subtract pattern penalties; clamp to 0..10.
    """
    tips = []
    score = 0
    L = len(password)
    if L >= 8:  score += 2
    if L >= 12: score += 2
    if L >= 16: score += 1
    _, flags = detect_charset_size(password)
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
    """
    k-anonymity: send first 5 hex chars of SHA1, search suffixes locally.
    No API key needed for Pwned Passwords range API.
    """
    if not password:
        return None
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true", "User-Agent": "PasswordSecurityLab/1.0"}
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
    """
    Simple model: try dictionary words (case-insensitive), then a few common
    rules (capitalize first, add 1–4 digits). Returns (seconds, likely_found?).
    """
    pw_lower = password.lower()
    dict_list = [w.strip().lower() for w in dictionary if w.strip()]
    dict_set = set(dict_list)

    # Quick direct hit check
    if pw_lower in dict_set:
        # approximate index-based time (not exact but fine for estimation)
        try_index = dict_list.index(pw_lower) + 1
        return try_index / max(words_per_sec, 1e-30), True

    # Rules-based rough attempt count
    attempts = 0
    found = False
    for w in dict_set:
        attempts += 1  # plain
        if w == pw_lower:
            found = True
            break
        wc = w.capitalize()
        attempts += 1
        if wc == password:
            found = True
            break
        # append 1 to 4 digits (we count attempts, not enumerate fully)
        for dlen in (1,2,3,4):
            attempts += (10 ** dlen)
            if password.startswith(w) or password.startswith(wc):
                tail = password[len(w):] if password.startswith(w) else password[len(wc):]
                if tail.isdigit() and 1 <= len(tail) <= 4:
                    found = True
                    break
        if found:
            break
    secs = attempts / max(words_per_sec, 1e-30)
    return secs, found

def estimate_hybrid_time(password: str, dictionary: List[str], attempts_per_sec: float) -> float:
    """
    Hybrid: assume attacker uses smart masks & mangling.
    Reduce effective keyspace depending on detected patterns.
    """
    penalties, _ = pattern_penalties(password)
    ks, _ = keyspace(password)
    if penalties >= 2:
        eff = ks ** 0.5
    elif penalties == 1:
        eff = ks ** 0.7
    else:
        eff = ks ** 0.9
    trials = eff / 2
    return trials / max(attempts_per_sec, 1e-30)

# ============= UI =============
st.title("🔐 Advanced Password Security Lab")
st.caption("Runs locally; breach check uses k-anonymity (no password leaves your machine in plain form).")

with st.expander("What’s inside?"):
    st.markdown(
        """
- **Strength analyzer** with pattern detection  
- **Entropy**: Shannon & keyspace-based  
- **Breach lookup** via Have I Been Pwned (range API)  
- **Attack models**: Brute-force, Dictionary, Hybrid (smart rules)  
- **Live chart**: crack time vs length (log scale)  
- **PDF export** for your report/black book  
        """
    )

# -------- Controls --------
with st.sidebar:
    st.header("⚙️ Settings")
    online_check = st.toggle("Enable Breach Check (HIBP)", value=True, help="Queries Pwned Passwords range API with SHA-1 prefix (k-anonymity).")
    brute_speed = st.number_input("Brute-force attempts/sec", value=DEFAULT_BRUTEFORCE_SPEED, step=1e7, format="%.0f")
    dict_speed  = st.number_input("Dictionary tries/sec", value=DEFAULT_DICT_SPEED, step=1e3, format="%.0f")
    hybrid_speed= st.number_input("Hybrid attempts/sec", value=DEFAULT_HYBRID_SPEED, step=1e6, format="%.0f")

    st.subheader("Dictionary Upload (optional)")
    dict_file = st.file_uploader("Upload dictionary (.txt)", type=["txt"], help="One password per line (e.g., rockyou.txt).")

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

dictionary = load_dictionary(dict_file)

# -------- Password Analysis --------
st.header("1) Analyze a Password")
password = st.text_input("Enter a password (processed locally):", type="password")

if password:
    # Score & tips
    score, tips = strength_score(password)
    st.write(f"**Strength score:** {score}/10")
    st.progress(score / 10)

    # Entropy
    ks, charset_size = keyspace(password)
    entropy_bits_keyspace = len(password) * log2(charset_size)
    entropy_bits_shannon  = shannon_entropy_bits(password)

    colA, colB = st.columns(2)
    with colA:
        st.write(f"**Detected charset size:** `{charset_size}`")
        st.write(f"**Keyspace:** `{ks:,}` combinations")
        st.write(f"**Keyspace entropy:** `{entropy_bits_keyspace:.2f}` bits")
    with colB:
        st.write(f"**Shannon entropy:** `{entropy_bits_shannon:.2f}` bits")
        seqs = find_sequences(password, 3)
        if seqs:
            st.write(f"**Sequences:** {', '.join(seqs)}")
        yr = looks_like_year(password)
        if yr:
            st.write(f"**Year-like:** {yr}")

    # Breach check
    breached_count = None
    if online_check:
        with st.spinner("Checking Have I Been Pwned (k-anonymity)…"):
            breached_count = hibp_breach_count(password)
    if breached_count is not None:
        if breached_count > 0:
            st.error(f"⚠ Found in known breaches **{breached_count:,}** times.")
        else:
            st.success("✅ Not found in the HIBP dataset (good sign, but still use unique passwords).")
    else:
        st.info("Breach check unavailable (offline or API issue).")

    # Attack models on this exact password
    avg_brute_time  = estimate_bruteforce_time(ks, brute_speed, average=True)
    worst_brute_time= estimate_bruteforce_time(ks, brute_speed, average=False)
    dict_time, dict_found = estimate_dictionary_time(password, dictionary, dict_speed)
    hybrid_time = estimate_hybrid_time(password, dictionary, hybrid_speed)

    st.subheader("Estimated Crack Times (this exact password)")
    st.write(f"**Brute-force (average):** {pretty_time(avg_brute_time)}")
    st.write(f"**Brute-force (worst):** {pretty_time(worst_brute_time)}")
    st.write(f"**Dictionary attack:** {pretty_time(dict_time)} {'(likely hit ✅)' if dict_found else '(unlikely hit ❌)'}")
    st.write(f"**Hybrid (smart rules):** {pretty_time(hybrid_time)}")

    # Tips
    if tips:
        st.subheader("Suggestions")
        for t in tips:
            st.write("- " + t)
    else:
        st.success("Looks strong. Prefer long, unique passphrases and a password manager.")

else:
    st.info("Type a password above to analyze it with entropy, patterns, breach check, and attack estimates.")

# -------- Chart: by Length --------
st.header("2) Live Chart — Crack Time vs Length")
col1, col2 = st.columns(2)
with col1:
    selected_sets = st.multiselect(
        "Character sets to include",
        list(CHARSETS.keys()),
        default=["Lowercase (a-z)", "Uppercase (A-Z)", "Digits (0-9)"]
    )
with col2:
    max_len = st.slider("Max password length", min_value=6, max_value=40, value=24)

lengths = list(range(1, max_len + 1))
ks_times, dict_times, hybrid_times = [], [], []

for L in lengths:
    ks_L, _ = keyspace_by_length(L, selected_sets)
    ks_times.append(estimate_bruteforce_time(ks_L, brute_speed, average=True))
    variants = min(len(dictionary) * max(1, L - 4), 2_000_000)  # heuristic for visualization
    dict_times.append(variants / max(dict_speed, 1e-30))
    eff = (ks_L ** 0.85)  # heuristic reduction for smart rules
    hybrid_times.append((eff / 2) / max(hybrid_speed, 1e-30))

fig, ax = plt.subplots()
ax.plot(lengths, ks_times, marker="o", label="Brute-force (avg)")
ax.plot(lengths, dict_times, marker="o", label="Dictionary")
ax.plot(lengths, hybrid_times, marker="o", label="Hybrid (smart)")
ax.set_yscale("log")
ax.set_xlabel("Password Length")
ax.set_ylabel("Estimated Time (seconds, log scale)")
ax.set_title("Crack Time vs Password Length — Multiple Attack Models")
ax.legend()
yticks = [1, 60, 3600, 86400, 31_557_600, 31_557_600*1000, 31_557_600*1_000_000]
ax.set_yticks(yticks)
ax.set_yticklabels(["1 sec","1 min","1 hr","1 day","1 yr","1k yrs","1M yrs"])
st.pyplot(fig)

st.caption("Educational estimates. Real attacks vary with hashing (bcrypt/argon2/scrypt), salting, rate-limits, 2FA, and attacker capabilities.")

# -------- PDF Report --------
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.lib.units import inch

def make_pdf_report(pw: str,
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
                    hybrid_t: Optional[float]) -> bytes:
    buffer = io.BytesIO()
    c = pdf_canvas.Canvas(buffer, pagesize=A4)
    w, h = A4
    x = inch * 0.8
    y = h - inch * 0.8

    def line(t, dy=14):
        nonlocal y
        c.drawString(x, y, t)
        y -= dy

    c.setFont("Helvetica-Bold", 16)
    line("Advanced Password Security Report", 20)
    c.setFont("Helvetica", 10)

    display_pw = "(hidden)" if not pw else ("*" * min(8, len(pw))) + ("…" if len(pw) > 8 else "")
    line(f"Password (masked): {display_pw}")
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
    line("Notes:")
    line("  - Estimates depend on attacker speed & defenses (hashing/2FA/rate limits).")
    line("  - Use long, unique passphrases and a password manager.")

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()

st.header("3) Export Report (PDF)")
if st.button("Generate PDF"):
    if password:
        score, _tips = strength_score(password)
        ks_val, cs = keyspace(password)
        Hk = len(password) * log2(cs)
        Hs = shannon_entropy_bits(password)
        breached = hibp_breach_count(password) if online_check else None
        bf_avg  = estimate_bruteforce_time(ks_val, brute_speed, average=True)
        bf_worst= estimate_bruteforce_time(ks_val, brute_speed, average=False)
        dict_t, dict_hit = estimate_dictionary_time(password, dictionary, dict_speed)
        hyb_t = estimate_hybrid_time(password, dictionary, hybrid_speed)
        pdf_bytes = make_pdf_report(password, score, ks_val, cs, Hk, Hs, breached, bf_avg, bf_worst, dict_t, dict_hit, hyb_t)
        st.download_button("Download PDF Report", data=pdf_bytes, file_name="password_security_report.pdf", mime="application/pdf")
    else:
        st.warning("Enter a password first to include in the report.")

# ---- Footer ----
st.markdown("---")
st.markdown("Made for education & college projects. Respect rate limits for HIBP (no API key required for range endpoint).")
