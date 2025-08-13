import math
import streamlit as st
import matplotlib.pyplot as plt

# ===== Character sets =====
CHARSETS = {
    "Lowercase (a-z)": 26,
    "Uppercase (A-Z)": 26,
    "Digits (0-9)": 10,
    "Symbols (!@#...)": 32,
    "All printable ASCII": 95
}

# ===== Weak password list (sample) =====
WEAK_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123",
    "111111", "123123", "password1", "iloveyou", "admin"
}

# ===== Helper functions =====
def log2(x):
    return math.log(x, 2)

def pretty_time(seconds):
    if seconds == float("inf"):
        return "infinite"
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

def calc_keyspace(password):
    sets_used = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if has_lower: sets_used += CHARSETS["Lowercase (a-z)"]
    if has_upper: sets_used += CHARSETS["Uppercase (A-Z)"]
    if has_digit: sets_used += CHARSETS["Digits (0-9)"]
    if has_symbol: sets_used += CHARSETS["Symbols (!@#...)"]

    if sets_used == 0:
        sets_used = CHARSETS["All printable ASCII"]

    return sets_used ** len(password), sets_used

def calc_keyspace_length(length, selected_sets):
    size = sum(CHARSETS[name] for name in selected_sets)
    if size == 0:
        size = CHARSETS["All printable ASCII"]
    return size ** length, size

def estimate_time_length(length, selected_sets, attempts_per_sec, avg_case=True):
    keyspace, _ = calc_keyspace_length(length, selected_sets)
    trials = keyspace / 2 if avg_case else keyspace
    return trials / attempts_per_sec

def estimate_time(password, attempts_per_sec, avg_case=True):
    keyspace, _ = calc_keyspace(password)
    trials = keyspace / 2 if avg_case else keyspace
    return trials / attempts_per_sec

def strength_score(password):
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(not c.isalnum() for c in password): score += 1
    if password.lower() not in WEAK_PASSWORDS: score += 1
    return score

def improvement_tips(password):
    tips = []
    if len(password) < 12:
        tips.append("Make it at least 12 characters long.")
    if not any(c.islower() for c in password):
        tips.append("Add some lowercase letters.")
    if not any(c.isupper() for c in password):
        tips.append("Add some uppercase letters.")
    if not any(c.isdigit() for c in password):
        tips.append("Include some numbers.")
    if not any(not c.isalnum() for c in password):
        tips.append("Include some special characters (e.g., !, @, #).")
    if password.lower() in WEAK_PASSWORDS:
        tips.append("Avoid common passwords.")
    return tips

# ===== Streamlit UI =====
st.set_page_config(page_title="Password Strength & Brute-force Chart", layout="centered")
st.title("🔐 Password Strength Checker + Brute-force Time Chart")
st.markdown("Educational tool to check password strength and estimate brute-force time. **Runs locally — no passwords are sent anywhere.**")

# ==== Password Strength Section ====
password = st.text_input("Enter a password to check:", type="password")

if password:
    if password.lower() in WEAK_PASSWORDS:
        st.error("⚠ This is a **common weak password** — easily cracked!")

    score = strength_score(password)
    st.markdown(f"**Strength Score:** {score}/7")
    st.progress(score / 7)

    keyspace, charset_size = calc_keyspace(password)
    entropy_bits = len(password) * log2(charset_size)

    st.write(f"**Character set size:** {charset_size}")
    st.write(f"**Keyspace:** {keyspace:,} combinations")
    st.write(f"**Entropy:** {entropy_bits:.2f} bits")

    attempts_per_sec = st.number_input("Attacker speed (attempts/sec):", value=1e6, step=1e5, format="%.0f")
    time_avg = estimate_time(password, attempts_per_sec, avg_case=True)
    time_worst = estimate_time(password, attempts_per_sec, avg_case=False)

    st.write(f"**Average-case crack time:** {pretty_time(time_avg)}")
    st.write(f"**Worst-case crack time:** {pretty_time(time_worst)}")

    tips = improvement_tips(password)
    if tips:
        st.subheader("🔧 Suggestions to improve password:")
        for tip in tips:
            st.write("- " + tip)
    else:
        st.success("✅ Your password is strong!")

# ==== Real-time Chart Section ====
st.subheader("📊 Crack Time vs Password Length")

selected_sets = st.multiselect(
    "Character sets included in password:",
    list(CHARSETS.keys()),
    default=["Lowercase (a-z)", "Uppercase (A-Z)", "Digits (0-9)"]
)

chart_speed = st.number_input("Attacker speed for chart (attempts/sec):", value=1e9, step=1e7, format="%.0f")
max_length = st.slider("Max password length to plot:", min_value=5, max_value=40, value=20)

lengths = list(range(1, max_length + 1))
times = [estimate_time_length(l, selected_sets, chart_speed, avg_case=True) for l in lengths]

# Create chart
fig, ax = plt.subplots()
ax.plot(lengths, times, marker="o")
ax.set_yscale("log")  # Log scale for time
ax.set_xlabel("Password Length")
ax.set_ylabel("Average Crack Time (seconds, log scale)")
ax.set_title("Crack Time vs Password Length")

# Format y-axis labels as pretty time
ax.set_yticks([1, 60, 3600, 86400, 31557600, 31557600*1000])
ax.set_yticklabels([
    "1 sec", "1 min", "1 hr", "1 day", "1 yr", "1000 yrs"
])

st.pyplot(fig)
# password_security_app.py
# Safe, local educational app: password strength + brute-force estimator + live chart

import math
import streamlit as st
import matplotlib.pyplot as plt

# ----------------- Constants -----------------
CHARSETS = {
    "Lowercase (a-z)": 26,
    "Uppercase (A-Z)": 26,
    "Digits (0-9)": 10,
    "Symbols (!@#...)": 32,
    "All printable ASCII": 95,
}

# Small sample list; you can expand it later
WEAK_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123",
    "111111", "123123", "password1", "iloveyou", "admin",
}

# ----------------- Helpers -----------------
def log2(x: float) -> float:
    return math.log(x, 2)

def pretty_time(seconds: float) -> str:
    if seconds == float("inf") or seconds > 1e300:
        return "practically infinite"
    if seconds < 1e-6:
        return "≈ 0 sec"

    s = int(seconds)
    parts = []
    units = [
        ("year", 365 * 24 * 3600),
        ("day", 24 * 3600),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]
    for name, val in units:
        if s >= val:
            qty = s // val
            s -= qty * val
            parts.append(f"{qty} {name}{'s' if qty != 1 else ''}")
    return ", ".join(parts) if parts else "0 seconds"

def detect_sets(password: str):
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
    return size, has_lower, has_upper, has_digit, has_symbol

def calc_keyspace_len(length: int, selected_sets: list[str]) -> tuple[int, int]:
    size = sum(CHARSETS[name] for name in selected_sets) if selected_sets else 0
    if size == 0:
        size = CHARSETS["All printable ASCII"]
    # Python ints are arbitrary precision, so this is safe
    return size ** length, size

def calc_keyspace_pwd(password: str) -> tuple[int, int]:
    size, *_ = detect_sets(password)
    return size ** len(password), size

def estimate_time_by_len(length: int, selected_sets: list[str], attempts_per_sec: float, average=True) -> float:
    keyspace, _ = calc_keyspace_len(length, selected_sets)
    trials = keyspace / 2 if average else keyspace
    return trials / max(attempts_per_sec, 1e-30)

def estimate_time_by_pwd(password: str, attempts_per_sec: float, average=True) -> float:
    keyspace, _ = calc_keyspace_pwd(password)
    trials = keyspace / 2 if average else keyspace
    return trials / max(attempts_per_sec, 1e-30)

def strength_score(password: str) -> int:
    score = 0
    if len(password) >= 8:  score += 1
    if len(password) >= 12: score += 1
    if any(c.islower() for c in password):  score += 1
    if any(c.isupper() for c in password):  score += 1
    if any(c.isdigit() for c in password):  score += 1
    if any(not c.isalnum() for c in password): score += 1
    if password.lower() not in WEAK_PASSWORDS: score += 1
    return score  # /7

def improvement_tips(password: str) -> list[str]:
    tips = []
    if len(password) < 12: tips.append("Increase length to at least 12 characters (more is better).")
    if not any(c.islower() for c in password):  tips.append("Add lowercase letters.")
    if not any(c.isupper() for c in password):  tips.append("Add uppercase letters.")
    if not any(c.isdigit() for c in password):  tips.append("Include some digits.")
    if not any(not c.isalnum() for c in password): tips.append("Include special characters (e.g., ! @ #).")
    if password.lower() in WEAK_PASSWORDS: tips.append("Avoid common/known weak passwords.")
    return tips

# ----------------- Streamlit UI -----------------
st.set_page_config(page_title="Password Security App", layout="centered")
st.title("🔐 Password Strength + Brute-force Estimator (Safe, Local)")

st.markdown(
    "This tool runs **locally** and does **not** send your input anywhere. "
    "It estimates strength (entropy/keyspace) and brute-force time using math — "
    "no real cracking is performed."
)

with st.expander("What does it do?"):
    st.markdown(
        "- **Strength check**: score, keyspace, entropy, tips\n"
        "- **Brute-force estimator**: average & worst-case time\n"
        "- **Live chart**: crack time vs password length (log scale)\n"
    )

# -------- Password section --------
st.header("1) Check a Password")
password = st.text_input("Enter a password (local only):", type="password")

if password:
    # Known-weak check
    if password.lower() in WEAK_PASSWORDS:
        st.error("⚠ This is a **common weak password**. Change it immediately.")

    # Score bar
    score = strength_score(password)
    st.write(f"**Strength score:** {score}/7")
    st.progress(score / 7)

    # Keyspace / entropy
    keyspace, charset_size = calc_keyspace_pwd(password)
    entropy_bits = len(password) * log2(charset_size)
    st.write(f"**Detected character set size:** `{charset_size}`")
    st.write(f"**Keyspace:** `{keyspace:,}` combinations")
    st.write(f"**Entropy:** `{entropy_bits:.2f}` bits")

    # Estimation
    attempts = st.number_input("Attacker speed (attempts/second):", value=1e6, step=1e5, format="%.0f")
    avg_time = estimate_time_by_pwd(password, attempts, average=True)
    worst_time = estimate_time_by_pwd(password, attempts, average=False)

    st.write(f"**Average-case time:** {pretty_time(avg_time)}")
    st.write(f"**Worst-case time:** {pretty_time(worst_time)}")

    # Tips
    tips = improvement_tips(password)
    if tips:
        st.subheader("Suggestions")
        for t in tips:
            st.write("- " + t)
    else:
        st.success("✅ Looks strong based on these basic checks. (Long unique passphrases are best.)")
else:
    st.info("Type a password above to see strength, estimates, and tips.")

# -------- Chart section --------
st.header("2) Real-time Chart: Crack Time vs Password Length")

col1, col2 = st.columns(2)
with col1:
    selected_sets = st.multiselect(
        "Character sets to include",
        list(CHARSETS.keys()),
        default=["Lowercase (a-z)", "Uppercase (A-Z)", "Digits (0-9)"]
    )
with col2:
    chart_attempts = st.number_input(
        "Attacker speed for chart (attempts/sec)",
        value=1e9, step=1e7, format="%.0f"
    )

max_length = st.slider("Max password length to plot", min_value=6, max_value=40, value=24)

lengths = list(range(1, max_length + 1))
times_avg = [estimate_time_by_len(L, selected_sets, chart_attempts, average=True) for L in lengths]

# Draw chart
fig, ax = plt.subplots()
ax.plot(lengths, times_avg, marker="o")
ax.set_yscale("log")
ax.set_xlabel("Password Length")
ax.set_ylabel("Average Crack Time (seconds, log scale)")
ax.set_title("Crack Time vs Password Length")

# Helpful guide ticks (approx)
yticks = [1, 60, 3600, 86400, 31557600, 31557600*1000, 31557600*1000*1000]
ylabels = ["1 sec", "1 min", "1 hr", "1 day", "1 yr", "1,000 yrs", "1,000,000 yrs"]
ax.set_yticks(yticks)
ax.set_yticklabels(ylabels)

st.pyplot(fig)

st.caption("Note: These are estimates based on math. Real-world defenses (rate limits, 2FA, strong hashing like bcrypt/argon2) make online attacks much slower.")
