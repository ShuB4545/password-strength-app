
import math
import hashlib
import requests
import io
import random
import time
from collections import Counter
from typing import List, Tuple, Dict, Optional

import streamlit as st
import matplotlib.pyplot as plt
import pandas as pd

# Optional bcrypt (slow hashing demo)
try:
    import bcrypt
    HAS_BCRYPT = True
except Exception:
    HAS_BCRYPT = False

# ReportLab for PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.lib.units import inch

# ========================= Page Config & CSS =========================
st.set_page_config(page_title="Advanced Password Security Lab — Extended", layout="wide", page_icon="🔐")

DARK_CSS = """
<style>
    .stApp { background-color: #0b1220; color: #e5e7eb; }
    h1, h2, h3, h4 { color: #e5e7eb; }
    .stButton>button, .stDownloadButton>button { border-radius: 10px; padding: 0.5rem 1rem; }
    .stProgress > div > div > div { background-image: linear-gradient(90deg, #34d399, #60a5fa); }
    .pill { display:inline-block; padding: 2px 8px; border-radius: 999px; background:#111827; color:#93c5fd; margin-right:6px; font-size:12px; }
</style>
"""
st.markdown(DARK_CSS, unsafe_allow_html=True)

# ========================= Translations =========================
# NOTE: If you add UI text, also add its translation here with the same key.
T = {
    "en": {
        "app_title": "🔐 Advanced Password Security Lab — Extended",
        "app_caption": "Educational tool: local analysis; HIBP uses k‑anonymity for breach checks.",
        "whats_new": "What's new in this multilingual extended version?",
        "whats_new_points": "- Extra pattern detectors (palindrome, repeated substrings, keyboard walks)\n- Hash algorithm simulator (bcrypt optional)\n- Passphrase generator & history\n- Attack charts and scenarios\n- Full English/Hindi/Marathi UI and PDF\n- CSV/PDF exports",

        "sidebar_settings": "⚙️ Settings & Tools",
        "language": "Language / भाषा / भाषा निवडा",
        "english": "English",
        "hindi": "हिंदी",
        "marathi": "मराठी",
        "hibp_toggle": "Enable Breach Check (HIBP)",
        "brute_speed": "Brute‑force attempts/sec",
        "dict_speed": "Dictionary tries/sec",
        "hybrid_speed": "Hybrid attempts/sec",
        "bcrypt_rounds": "bcrypt rounds (if available)",
        "dict_upload": "Load dictionary (optional)",
        "upload_wordlist": "Upload wordlist (.txt)",
        "bcrypt_ok": "bcrypt library available",
        "bcrypt_missing": "bcrypt not installed — bcrypt simulation disabled (optional).",

        "analyze_header": "Analyze a Password",
        "enter_password": "Enter a password (processed locally):",
        "strength": "Strength",
        "entropy_keyspace": "Entropy & Keyspace",
        "charset_size": "Charset size",
        "keyspace": "Keyspace",
        "keyspace_entropy": "Keyspace entropy",
        "shannon_entropy": "Shannon entropy",
        "patterns_found": "Patterns found",
        "checking_hibp": "Checking Have I Been Pwned (k‑anonymity)…",
        "found_breaches": "Found in known breaches {n} times.",
        "not_found_breaches": "Not found in HIBP dataset (still use unique passwords).",
        "breach_unavailable": "Breach check unavailable or offline.",

        "estimates_header": "Estimated Crack Times",
        "brute_avg": "Brute‑force (average)",
        "brute_worst": "Brute‑force (worst)",
        "dictionary_attack": "Dictionary",
        "likely_hit": "likely hit",
        "unlikely_hit": "unlikely",
        "hybrid_attack": "Hybrid",

        "hash_sim_header": "Hashing simulator (sample)",
        "hash_algo": "Hash algorithm to sample",
        "hash_compute_time": "computation time",

        "tips_header": "Suggestions & Tips",
        "looks_strong": "Password looks strong. Use long passphrases and a password manager.",
        "tip_len": "Increase length to at least 12 characters (passphrases are great).",
        "tip_lower": "Add lowercase letters.",
        "tip_upper": "Add uppercase letters.",
        "tip_digit": "Include digits.",
        "tip_symbol": "Include special characters (!@#...).",
        "tip_common": "Avoid common or leaked passwords.",

        "save_to_history": "Save analysis to history",
        "saved_history": "Saved to history",
        "type_password": "Type a password above to analyze it (keeps analysis local).",

        "passphrase_header": "Passphrase Generator",
        "words_in_pass": "Words in passphrase",
        "separator": "Separator",
        "use_uploaded": "Use uploaded dictionary as wordlist (if available)",
        "generate_pass": "Generate Passphrase",
        "generated_pass": "Generated Passphrase",
        "copy_pass": "Copy passphrase to clipboard",
        "clipboard_note": "(Use your browser/OS clipboard — Streamlit cannot always write to clipboard)",

        "visuals_header": "Quick Tools & Visuals",
        "entropy_vs_length": "Entropy vs Length",
        "charsets_to_include": "Character sets to include",
        "max_len_chart": "Max length for chart",
        "composition_header": "Password Composition (example)",
        "enter_sample": "Enter sample for composition chart (optional)",

        "scenarios_header": "Attack scenarios",
        "show_crack_times": "Show crack times for a sample passphrase",
        "scenario": "Scenario",
        "time": "Time",

        "history_header": "History & Exports",
        "no_history": "No history saved yet. Analyze a password and click 'Save analysis to history'.",
        "download_csv": "Download history (CSV)",
        "clear_history": "Clear history",

        "export_header": "Export Report",
        "generate_pdf": "Generate PDF for last analysis",
        "download_pdf": "Download PDF",
        "no_pass_for_pdf": "No passphrase available for PDF generation. Generate one or analyze a password first.",

        "footer": "Educational demo — not an enterprise auditor. Consider hashing policies, rate limiting, 2FA, and secure storage.",
        "about": "About"
    },
    "hi": {
        "app_title": "🔐 उन्नत पासवर्ड सुरक्षा लैब — विस्तारित",
        "app_caption": "शैक्षणिक उपकरण: स्थानीय विश्लेषण; HIBP उल्लंघन जाँच के लिए k-अनामिता का उपयोग करता है।",
        "whats_new": "इस बहुभाषी विस्तारित संस्करण में नया क्या है?",
        "whats_new_points": "- अतिरिक्त पैटर्न डिटेक्टर (पलिंड्रोम, दोहराए गए सबस्ट्रिंग, कीबोर्ड वॉक)\n- हैश एल्गोरिद्म सिम्युलेटर (bcrypt वैकल्पिक)\n- पासफ्रेज जेनरेटर और इतिहास\n- अटैक चार्ट और परिदृश्य\n- पूर्ण अंग्रेज़ी/हिंदी/मराठी UI और PDF\n- CSV/PDF निर्यात",

        "sidebar_settings": "⚙️ सेटिंग्स और टूल्स",
        "language": "Language / भाषा / भाषा निवडा",
        "english": "English",
        "hindi": "हिंदी",
        "marathi": "मराठी",
        "hibp_toggle": "उल्लंघन जाँच (HIBP) सक्षम करें",
        "brute_speed": "ब्रूट‑फोर्स प्रयास/सेकंड",
        "dict_speed": "डिक्शनरी प्रयास/सेकंड",
        "hybrid_speed": "हाइब्रिड प्रयास/सेकंड",
        "bcrypt_rounds": "bcrypt राउंड (यदि उपलब्ध)",
        "dict_upload": "डिक्शनरी लोड करें (वैकल्पिक)",
        "upload_wordlist": "वर्डलिस्ट अपलोड करें (.txt)",
        "bcrypt_ok": "bcrypt उपलब्ध है",
        "bcrypt_missing": "bcrypt इंस्टॉल नहीं है — सिम्युलेशन अक्षम (वैकल्पिक)।",

        "analyze_header": "पासवर्ड का विश्लेषण करें",
        "enter_password": "पासवर्ड दर्ज करें (स्थानीय रूप से संसाधित):",
        "strength": "मजबूती",
        "entropy_keyspace": "एंट्रॉपी और की‑स्पेस",
        "charset_size": "करेक्टर सेट आकार",
        "keyspace": "की‑स्पेस",
        "keyspace_entropy": "की‑स्पेस एंट्रॉपी",
        "shannon_entropy": "शैनन एंट्रॉपी",
        "patterns_found": "पैटर्न मिले",
        "checking_hibp": "Have I Been Pwned की जाँच हो रही है (k‑अनामिता)…",
        "found_breaches": "ज्ञात उल्लंघनों में {n} बार पाया गया।",
        "not_found_breaches": "HIBP डेटा सेट में नहीं मिला (फिर भी अनूठे पासवर्ड का उपयोग करें)।",
        "breach_unavailable": "उल्लंघन जाँच उपलब्ध नहीं है या ऑफ़लाइन है।",

        "estimates_header": "अनुमानित क्रैक समय",
        "brute_avg": "ब्रूट‑फोर्स (औसत)",
        "brute_worst": "ब्रूट‑फोर्स (सबसे खराब)",
        "dictionary_attack": "डिक्शनरी",
        "likely_hit": "संभावित हिट",
        "unlikely_hit": "असंभावित",
        "hybrid_attack": "हाइब्रिड",

        "hash_sim_header": "हैशिंग सिम्युलेटर (नमूना)",
        "hash_algo": "हैश एल्गोरिद्म चुनें",
        "hash_compute_time": "गणना समय",

        "tips_header": "सुझाव और टिप्स",
        "looks_strong": "पासवर्ड मजबूत दिखता है। लंबे पासफ्रेज और पासवर्ड मैनेजर का उपयोग करें।",
        "tip_len": "लंबाई कम से कम 12 अक्षर करें (पासफ्रेज उत्तम हैं)।",
        "tip_lower": "छोटे अक्षर जोड़ें।",
        "tip_upper": "बड़े अक्षर जोड़ें।",
        "tip_digit": "अंकों को शामिल करें।",
        "tip_symbol": "विशेष वर्ण शामिल करें (!@#...)।",
        "tip_common": "सामान्य या लीक पासवर्ड से बचें।",

        "save_to_history": "विश्लेषण इतिहास में सहेजें",
        "saved_history": "इतिहास में सहेजा गया",
        "type_password": "ऊपर पासवर्ड टाइप करें — विश्लेषण स्थानीय रहता है।",

        "passphrase_header": "पासफ्रेज जेनरेटर",
        "words_in_pass": "पासफ्रेज में शब्दों की संख्या",
        "separator": "विभाजक",
        "use_uploaded": "अपलोडेड डिक्शनरी को वर्डलिस्ट के रूप में उपयोग करें (यदि उपलब्ध)",
        "generate_pass": "पासफ्रेज उत्पन्न करें",
        "generated_pass": "उत्पन्न पासफ्रेज",
        "copy_pass": "पासफ्रेज कॉपी करें",
        "clipboard_note": "(ब्राउज़र/OS क्लिपबोर्ड का उपयोग करें — Streamlit हमेशा सीधे कॉपी नहीं कर सकता)",

        "visuals_header": "त्वरित टूल और विज़ुअल्स",
        "entropy_vs_length": "लंबाई के मुकाबले एंट्रॉपी",
        "charsets_to_include": "शामिल करने के लिए करेक्टर सेट",
        "max_len_chart": "चार्ट के लिए अधिकतम लंबाई",
        "composition_header": "पासवर्ड संरचना (उदाहरण)",
        "enter_sample": "संरचना चार्ट के लिए नमूना दर्ज करें (वैकल्पिक)",

        "scenarios_header": "अटैक परिदृश्य",
        "show_crack_times": "नमूना पासफ्रेज के लिए क्रैक समय दिखाएँ",
        "scenario": "परिदृश्य",
        "time": "समय",

        "history_header": "इतिहास और निर्यात",
        "no_history": "अभी तक कोई इतिहास नहीं। पासवर्ड का विश्लेषण करें और 'इतिहास में सहेजें' क्लिक करें।",
        "download_csv": "इतिहास डाउनलोड करें (CSV)",
        "clear_history": "इतिहास साफ़ करें",

        "export_header": "रिपोर्ट निर्यात",
        "generate_pdf": "आखिरी विश्लेषण के लिए PDF बनाएँ",
        "download_pdf": "PDF डाउनलोड करें",
        "no_pass_for_pdf": "PDF के लिए कोई पासफ्रेज उपलब्ध नहीं। पहले पासफ्रेज बनाएँ या पासवर्ड विश्लेषित करें।",

        "footer": "शैक्षणिक डेमो — एंटरप्राइज़ ऑडिटर नहीं। हैशिंग नीतियाँ, रेट लिमिटिंग, 2FA और सुरक्षित स्टोरेज पर विचार करें।",
        "about": "परिचय"
    },
    "mr": {
        "app_title": "🔐 उन्नत पासवर्ड सुरक्षा प्रयोगशाळा — विस्तारित",
        "app_caption": "শैक्षणिक साधन: स्थानिक विश्लेषण; HIBP मध्ये k‑अनामिकता वापरली जाते.",
        "whats_new": "या बहुभाषिक विस्तारित आवृत्तीमध्ये नवीन काय?",
        "whats_new_points": "- अतिरिक्त पॅटर्न तपासणी (पालिंड्रोम, पुनरावृत्ती सबस्ट्रिंग, कीबोर्ड वॉक)\n- हॅश अल्गोरिदम सिम्युलेटर (bcrypt वैकल्पिक)\n- पासफ्रेज जनरेटर आणि इतिहास\n- हल्ला चार्ट आणि परिदृश्य\n- संपूर्ण इंग्रजी/हिंदी/मराठी UI आणि PDF\n- CSV/PDF निर्यात",

        "sidebar_settings": "⚙️ सेटिंग्ज आणि साधने",
        "language": "Language / भाषा / भाषा निवडा",
        "english": "English",
        "hindi": "हिंदी",
        "marathi": "मराठी",
        "hibp_toggle": "उल्लंघन तपासणी (HIBP) सक्षम करा",
        "brute_speed": "ब्रूट‑फोर्स प्रयत्न/सेकंद",
        "dict_speed": "डिक्शनरी प्रयत्न/सेकंद",
        "hybrid_speed": "हायब्रिड प्रयत्न/सेकंद",
        "bcrypt_rounds": "bcrypt राउंड्स (उपलब्ध असल्यास)",
        "dict_upload": "डिक्शनरी लोड करा (ऐच्छिक)",
        "upload_wordlist": "वर्डलिस्ट अपलोड करा (.txt)",
        "bcrypt_ok": "bcrypt उपलब्ध आहे",
        "bcrypt_missing": "bcrypt इंस्टॉल नाही — सिम्युलेशन अक्षम (ऐच्छिक).",

        "analyze_header": "पासवर्ड विश्लेषण करा",
        "enter_password": "पासवर्ड टाका (स्थानिकरीत्या प्रक्रिया)",
        "strength": "मजबूती",
        "entropy_keyspace": "एन्ट्रॉपी आणि की‑स्पेस",
        "charset_size": "कॅरेक्टर सेट आकार",
        "keyspace": "की‑स्पेस",
        "keyspace_entropy": "की‑स्पेस एन्ट्रॉपी",
        "shannon_entropy": "शॅनन एन्ट्रॉपी",
        "patterns_found": "आढळलेले पॅटर्न",
        "checking_hibp": "Have I Been Pwned तपासत आहोत (k‑अनामिकता)…",
        "found_breaches": "ज्ञात उल्लंघनांमध्ये {n} वेळा आढळले.",
        "not_found_breaches": "HIBP डेटासेटमध्ये सापडले नाही (तरीही अद्वितीय पासवर्ड वापरा).",
        "breach_unavailable": "उल्लंघन तपासणी उपलब्ध नाही किंवा ऑफलाइन आहे.",

        "estimates_header": "अंदाजे क्रॅक वेळ",
        "brute_avg": "ब्रूट‑फोर्स (सरासरी)",
        "brute_worst": "ब्रूट‑फोर्स (सर्वात वाईट)",
        "dictionary_attack": "डिक्शनरी",
        "likely_hit": "हिट होण्याची शक्यता",
        "unlikely_hit": "असंभाव्य",
        "hybrid_attack": "हायब्रिड",

        "hash_sim_header": "हॅशिंग सिम्युलेटर (नमुना)",
        "hash_algo": "हॅश अल्गोरिदम निवडा",
        "hash_compute_time": "गणना वेळ",

        "tips_header": "सूचना आणि टिप्स",
        "looks_strong": "पासवर्ड मजबूत दिसतो. लांब पासफ्रेज आणि पासवर्ड मॅनेजर वापरा.",
        "tip_len": "लांबी किमान 12 अक्षरे करा (पासफ्रेज उत्तम).",
        "tip_lower": "लघ्वाक्षरे जोडा.",
        "tip_upper": "मोठी अक्षरे जोडा.",
        "tip_digit": "अंके समाविष्ट करा.",
        "tip_symbol": "विशेष चिन्हे समाविष्ट करा (!@#...).",
        "tip_common": "सामान्य/लीक पासवर्ड टाळा.",

        "save_to_history": "विश्लेषण इतिहासात जतन करा",
        "saved_history": "इतिहासात जतन केले",
        "type_password": "वर पासवर्ड टाइप करा — विश्लेषण स्थानिक राहते.",

        "passphrase_header": "पासफ्रेज जनरेटर",
        "words_in_pass": "पासफ्रेजमधील शब्दांची संख्या",
        "separator": "विभाजक",
        "use_uploaded": "अपलोड केलेली डिक्शनरी वर्डलिस्ट म्हणून वापरा (उपलब्ध असल्यास)",
        "generate_pass": "पासफ्रेज तयार करा",
        "generated_pass": "तयार केलेली पासफ्रेज",
        "copy_pass": "पासफ्रेज कॉपी करा",
        "clipboard_note": "(ब्राउझर/OS क्लिपबोर्ड वापरा — Streamlit नेहमी थेट कॉपी करू शकत नाही)",

        "visuals_header": "जलद साधने आणि दृश्ये",
        "entropy_vs_length": "लांबी विरुद्ध एन्ट्रॉपी",
        "charsets_to_include": "समाविष्ट करण्यासाठी कॅरेक्टर सेट",
        "max_len_chart": "चार्टसाठी कमाल लांबी",
        "composition_header": "पासवर्ड संरचना (उदाहरण)",
        "enter_sample": "संरचना चार्टसाठी नमुना प्रविष्ट करा (ऐच्छिक)",

        "scenarios_header": "हल्ल्याची परिदृश्ये",
        "show_crack_times": "नमुना पासफ्रेजसाठी क्रॅक वेळ दर्शवा",
        "scenario": "परिदृশ্য",
        "time": "वेळ",

        "history_header": "इतिहास आणि निर्यात",
        "no_history": "अजून इतिहास नाही. पासवर्डचे विश्लेषण करा आणि 'इतिहासात जतन करा' क्लिक करा.",
        "download_csv": "इतिहास डाउनलोड करा (CSV)",
        "clear_history": "इतिहास साफ करा",

        "export_header": "अहवाल निर्यात",
        "generate_pdf": "शेवटच्या विश्लेषणासाठी PDF तयार करा",
        "download_pdf": "PDF डाउनलोड करा",
        "no_pass_for_pdf": "PDF साठी पासफ्रेज उपलब्ध नाही. प्रथम पासफ्रेज तयार करा किंवा पासवर्ड विश्लेषित करा.",

        "footer": "शैक्षणिक डेमो — एंटरप्राइझ ऑडिटर नाही. हॅशिंग धोरणे, रेट-लिमिटिंग, 2FA आणि सुरक्षित स्टोरेज विचारात घ्या.",
        "about": "परिचय"
    },
}

# ========================= Constants & Samples =========================
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

KEYBOARD_ROWS = ["1234567890","qwertyuiop","asdfghjkl","zxcvbnm"]

DEFAULT_DICT_SAMPLE = [
    "password","qwerty","dragon","iloveyou","monkey","letmein",
    "football","admin","welcome","login","sunshine","princess"
]

DICEWARE_SAMPLE = [
    "alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel",
    "india","juliet","kilo","lima","mike","november","oscar","papa",
]

LEET_MAP = {"a":"4@","e":"3","i":"1!","o":"0","s":"$5","t":"7","+":"t"}

# ========================= Helpers =========================

def tr(lang: str, key: str, **fmt) -> str:
    """Translate a key for current language; fallback to English; format placeholders."""
    text = T.get(lang, {}).get(key, T["en"].get(key, key))
    if fmt:
        try:
            text = text.format(**fmt)
        except Exception:
            pass
    return text


def log2(x: float) -> float:
    return math.log(x, 2) if x > 0 else 0.0


def pretty_time(seconds: float) -> str:
    if seconds is None or seconds != seconds:
        return "n/a"
    if seconds == float("inf") or seconds > 1e300:
        return "practically infinite"
    if seconds < 1e-6:
        return "≈ 0 sec"
    s = int(seconds)
    units = [("year", 365*24*3600),("day",24*3600),("hour",3600),("minute",60),("second",1)]
    parts = []
    for name, val in units:
        if s >= val:
            qty = s // val
            s -= qty * val
            parts.append(f"{qty} {name}{'s' if qty != 1 else ''}")
    return ", ".join(parts) if parts else "0 seconds"


def detect_charset_size(password: str) -> Tuple[int, int, Dict[str, bool]]:
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    size = 0
    if has_lower:  size += CHARSETS["Lowercase (a-z)"]
    if has_upper:  size += CHARSETS["Uppercase (A-Z)"]
    if has_digit:  size += CHARSETS["Digits (0-9)"]
    if has_symbol: size += CHARSETS["Symbols (!@#...)"]
    if size == 0: size = CHARSETS["All printable ASCII"]
    flags = {"lower":has_lower,"upper":has_upper,"digit":has_digit,"symbol":has_symbol}
    return size ** len(password), size, flags


def keyspace_by_length(length: int, selected_sets: List[str]) -> Tuple[int, int]:
    size = sum(CHARSETS[n] for n in selected_sets) if selected_sets else 0
    if size == 0: size = CHARSETS["All printable ASCII"]
    return size ** length, size


def shannon_entropy_bits(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    n = len(s)
    H = 0.0
    for c in counts.values():
        p = c / n
        H -= p * math.log(p, 2)
    return H * n

# -------- Pattern detectors --------

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
    if not password: return None
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
            if seq in p: findings.append(seq)
        rev = row[::-1]
        for i in range(len(rev) - min_len + 1):
            seq = rev[i:i+min_len]
            if seq in p: findings.append(seq)
    return list(set(findings))


def pattern_penalties(password: str) -> Tuple[int, List[str]]:
    penalties = 0
    notes = []
    seqs = find_sequences(password, 3)
    if seqs:
        penalties += 1 + min(3, len(seqs)//2)
        notes.append("Sequential patterns: " + ', '.join(seqs))
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
    if is_palindrome(password):
        penalties += 1
        notes.append("Palindrome-like")
    kw = keyboard_walks(password, 4)
    if kw:
        penalties += 1
        notes.append("Keyboard walks: " + ', '.join(kw))
    dl = deleet(password)
    common_hits = [w for w in DEFAULT_DICT_SAMPLE if w in dl]
    if common_hits:
        penalties += 1
        notes.append("Common words after deleet: " + ', '.join(set(common_hits)))
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

# ========================= HIBP (Pwned Passwords) =========================
@st.cache_data(show_spinner=False, ttl=60*30)
def hibp_breach_count(password: str, timeout: float = 6.0) -> Optional[int]:
    if not password: return None
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

# ========================= Attack Models =========================

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
    if ks <= 0: ks = 1
    if penalties >= 3:   eff = ks ** 0.5
    elif penalties == 2: eff = ks ** 0.7
    else:                eff = ks ** 0.9
    trials = eff / 2
    return trials / max(attempts_per_sec, 1e-30)

# ========================= Hashing Simulator =========================

def hash_simulation(password: str, algo: str = "sha256", bcrypt_rounds: int = 12) -> Tuple[str, float]:
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
        start2 = time.time()
        salt = bcrypt.gensalt(rounds=bcrypt_rounds)
        bh = bcrypt.hashpw(password.encode(), salt)
        elapsed = time.time() - start2
        return (bh.decode() if isinstance(bh, bytes) else str(bh)), elapsed
    return hashlib.sha256(password.encode()).hexdigest(), time.time() - start

# ========================= Passphrase Generator =========================

def generate_passphrase(num_words: int = 4, separator: str = " ", wordlist: Optional[List[str]] = None) -> str:
    wl = wordlist or DICEWARE_SAMPLE
    words = [random.choice(wl) for _ in range(num_words)]
    return separator.join(words)

# ========================= Dictionary Loading =========================
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

# ========================= PDF Report =========================

def make_pdf_report(lang: str,
                    pw: str,
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
    line(tr(lang, "app_title"), 20)
    c.setFont("Helvetica", 10)

    display_pw = "(hidden)" if not pw else ("*" * min(8, len(pw))) + ("…" if len(pw) > 8 else "")
    line(f"Password (masked): {display_pw}")
    line(f"{tr(lang,'charset_size')}: {charset_size if charset_size is not None else 'n/a'}")
    line(f"{tr(lang,'keyspace')}: {format(ks, ',') if ks is not None else 'n/a'}")
    line(f"{tr(lang,'keyspace_entropy')}: {Hk:.2f}" if Hk is not None else f"{tr(lang,'keyspace_entropy')}: n/a")
    line(f"{tr(lang,'shannon_entropy')}: {Hs:.2f}" if Hs is not None else f"{tr(lang,'shannon_entropy')}: n/a")

    if breached is not None:
        if breached > 0:
            line(tr(lang, "found_breaches", n=f"{breached:,}"))
        else:
            line(tr(lang, "not_found_breaches"))
    else:
        line(tr(lang, "breach_unavailable"))

    line("")
    line(tr(lang, "estimates_header"))
    line(f"  • {tr(lang,'brute_avg')}: {pretty_time(bf_avg)}")
    line(f"  • {tr(lang,'brute_worst')}: {pretty_time(bf_worst)}")
    line(f"  • {tr(lang,'dictionary_attack')}: {pretty_time(dict_t)} {'('+tr(lang,'likely_hit')+')' if dict_hit else ''}")
    line(f"  • {tr(lang,'hybrid_attack')}: {pretty_time(hybrid_t)}")

    line("")
    if hash_algo:
        line(f"Hash: {hash_algo} — {tr(lang,'hash_compute_time')}: {hash_time:.4f} sec")

    line("")
    line("Notes:")
    line("  - Estimates depend on attacker speed & defenses (hashing/2FA/rate limits).")
    line("  - Use long, unique passphrases and a password manager.")

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.read()

# ========================= Session History =========================
if 'history' not in st.session_state:
    st.session_state.history = []


def add_to_history(entry: Dict):
    st.session_state.history.insert(0, entry)
    st.session_state.history = st.session_state.history[:25]

# ========================= UI =========================
# Language picker first (so we can translate everything below)
lang_choice = st.sidebar.selectbox(
    T['en']["language"],
    ["en","hi","mr"],
    index=0,
    format_func=lambda code: T['en']['english'] if code=='en' else (T['en']['hindi'] if code=='hi' else T['en']['marathi'])
)

st.title(tr(lang_choice, "app_title"))
st.caption(tr(lang_choice, "app_caption"))

# Sidebar controls
with st.sidebar:
    st.header(tr(lang_choice, "sidebar_settings"))
    online_check = st.checkbox(tr(lang_choice, "hibp_toggle"), value=True)
    brute_speed  = st.number_input(tr(lang_choice, "brute_speed"), value=1e9, step=1e7, format="%.0f")
    dict_speed   = st.number_input(tr(lang_choice, "dict_speed"),  value=2e4, step=1e3, format="%.0f")
    hybrid_speed = st.number_input(tr(lang_choice, "hybrid_speed"),value=5e7, step=1e6, format="%.0f")
    bcrypt_rounds= st.slider(tr(lang_choice, "bcrypt_rounds"), min_value=4, max_value=16, value=12)

    st.subheader(tr(lang_choice, "dict_upload"))
    dict_file = st.file_uploader(tr(lang_choice, "upload_wordlist"), type=["txt"]) 
    if HAS_BCRYPT:
        st.success(tr(lang_choice, "bcrypt_ok"))
    else:
        st.warning(tr(lang_choice, "bcrypt_missing"))

# Load dictionary (cached)
dictionary = load_dictionary(dict_file)

# Tabs for clean UX
tab_analyze, tab_visuals, tab_history, tab_about = st.tabs([
    tr(lang_choice, "analyze_header"),
    tr(lang_choice, "visuals_header"),
    tr(lang_choice, "history_header"),
    tr(lang_choice, "about"),
])

# ========================= Analyze Tab =========================
with tab_analyze:
    password = st.text_input(tr(lang_choice, "enter_password"), type="password")

    if password:
        # Save last analyzed password (masked and raw for PDF)
        st.session_state.last_password_raw = password
        st.session_state.last_password_masked = ('*'*min(8,len(password))) + ('…' if len(password)>8 else '')

        score, tips_en = strength_score(password)
        st.subheader(f"{tr(lang_choice,'strength')}: {score}/10")
        st.progress(score/10)

        ks_val, cs, flags = detect_charset_size(password)
        entropy_bits_keyspace = len(password) * (log2(cs) if cs>0 else 0)
        entropy_bits_shannon  = shannon_entropy_bits(password)

        st.write(f"**{tr(lang_choice,'entropy_keyspace')}**")
        st.write(f"{tr(lang_choice,'charset_size')}: `{cs}` — {tr(lang_choice,'keyspace')}: `{ks_val:,}`")
        st.write(f"{tr(lang_choice,'keyspace_entropy')}: `{entropy_bits_keyspace:.2f}` bits — {tr(lang_choice,'shannon_entropy')}: `{entropy_bits_shannon:.2f}` bits")

        p_penalty, p_notes = pattern_penalties(password)
        if p_notes:
            st.warning(tr(lang_choice, "patterns_found") + ": " + "; ".join(p_notes))

        breached_count = None
        if online_check:
            with st.spinner(tr(lang_choice, "checking_hibp")):
                breached_count = hibp_breach_count(password)
        if breached_count is not None:
            if breached_count > 0:
                st.error(tr(lang_choice, "found_breaches", n=f"{breached_count:,}"))
            else:
                st.success("✅ " + tr(lang_choice, "not_found_breaches"))
        else:
            st.info(tr(lang_choice, "breach_unavailable"))

        avg_brute_time  = estimate_bruteforce_time(ks_val, brute_speed, average=True)
        worst_brute_time= estimate_bruteforce_time(ks_val, brute_speed, average=False)
        dict_time, dict_found = estimate_dictionary_time(password, dictionary, dict_speed)
        hybrid_time = estimate_hybrid_time(password, dictionary, hybrid_speed)

        st.subheader(tr(lang_choice, "estimates_header"))
        st.write(f"{tr(lang_choice,'brute_avg')}: {pretty_time(avg_brute_time)} — ({tr(lang_choice,'brute_worst')}: {pretty_time(worst_brute_time)})")
        st.write(f"{tr(lang_choice,'dictionary_attack')}: {pretty_time(dict_time)} {'('+tr(lang_choice,'likely_hit')+' ✅)' if dict_found else '('+tr(lang_choice,'unlikely_hit')+' ❌)'}")
        st.write(f"{tr(lang_choice,'hybrid_attack')}: {pretty_time(hybrid_time)}")

        st.subheader(tr(lang_choice, "hash_sim_header"))
        algo_options = ["sha256","sha1","md5","bcrypt"] if HAS_BCRYPT else ["sha256","sha1","md5"]
        hash_algo = st.selectbox(tr(lang_choice, "hash_algo"), algo_options)
        hash_val, hash_time = hash_simulation(password, algo=hash_algo, bcrypt_rounds=bcrypt_rounds)
        st.write(f"{tr(lang_choice,'hash_compute_time')}: {hash_time:.4f} sec")
        st.code(str(hash_val)[:120] + ("..." if len(str(hash_val))>120 else ""))

        st.subheader(tr(lang_choice, "tips_header"))
        tips_map = {
            "Increase length to at least 12 characters (passphrases are great).": tr(lang_choice, "tip_len"),
            "Add lowercase letters.": tr(lang_choice, "tip_lower"),
            "Add uppercase letters.": tr(lang_choice, "tip_upper"),
            "Include digits.": tr(lang_choice, "tip_digit"),
            "Include special characters (!@#...).": tr(lang_choice, "tip_symbol"),
            "Avoid common or leaked passwords.": tr(lang_choice, "tip_common"),
        }
        rendered_any = False
        for t in tips_en:
            if t in tips_map:
                st.write("- " + tips_map[t])
                rendered_any = True
        if not rendered_any:
            st.success(tr(lang_choice, "looks_strong"))

        if st.button(tr(lang_choice, "save_to_history")):
            entry = {
                'time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'masked': st.session_state.last_password_masked,
                'score': score,
                'ks_entropy': round(entropy_bits_keyspace,2),
                'shannon': round(entropy_bits_shannon,2),
                'breached': breached_count if breached_count is not None else 'n/a'
            }
            add_to_history(entry)
            st.success(tr(lang_choice, "saved_history"))
    else:
        st.info(tr(lang_choice, "type_password"))

# ========================= Visuals & Tools Tab =========================
with tab_visuals:
    # Passphrase generator first
    st.header(tr(lang_choice, "passphrase_header"))
    colA, colB = st.columns([2,1])
    with colA:
        num_words = st.slider(tr(lang_choice, "words_in_pass"), min_value=3, max_value=8, value=4)
        separator = st.selectbox(tr(lang_choice, "separator"), [" ", "-", "_"]) 
        use_wordlist = st.checkbox(tr(lang_choice, "use_uploaded"), value=False)
    with colB:
        if st.button(tr(lang_choice, "generate_pass")):
            wl = dictionary if use_wordlist and dictionary else DICEWARE_SAMPLE
            phrase = generate_passphrase(num_words=num_words, separator=separator, wordlist=wl)
            st.session_state.generated_passphrase = phrase
            # Mark as last for PDF if needed
            st.session_state.last_password_raw = phrase
            st.session_state.last_password_masked = ('*'*min(8,len(phrase))) + ('…' if len(phrase)>8 else '')
    if 'generated_passphrase' in st.session_state:
        st.text_input(tr(lang_choice, "generated_pass"), value=st.session_state.generated_passphrase, key='gen_pass', disabled=True)
        if st.button(tr(lang_choice, "copy_pass")):
            st.write(tr(lang_choice, "clipboard_note"))

    st.header(tr(lang_choice, "entropy_vs_length"))
    selected_sets = st.multiselect(tr(lang_choice, "charsets_to_include"), list(CHARSETS.keys()), default=["Lowercase (a-z)", "Uppercase (A-Z)", "Digits (0-9)"])
    max_len = st.slider(tr(lang_choice, "max_len_chart"), min_value=6, max_value=40, value=24)

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
    ax1.plot(lengths, [max(1e-10,t) for t in dict_vis],      marker='o', label='Dictionary')
    ax1.plot(lengths, [max(1e-10,t) for t in hybrid_vis],    marker='o', label='Hybrid')
    ax1.set_yscale('log')
    ax1.set_xlabel('Length')
    ax1.set_ylabel('Estimated time (seconds, log)')
    ax1.legend()
    st.pyplot(fig1)

    st.subheader(tr(lang_choice, "composition_header"))
    sample = st.text_input(tr(lang_choice, "enter_sample"), key='comp_sample')
    if sample:
        counts = [sum(1 for c in sample if c.islower()), sum(1 for c in sample if c.isupper()), sum(1 for c in sample if c.isdigit()), sum(1 for c in sample if not c.isalnum())]
        labels = ['lower','upper','digits','symbols']
        if sum(counts) == 0:
            st.info("Enter at least one character to show composition.")
        else:
            fig2, ax2 = plt.subplots()
            ax2.pie(counts, labels=labels, autopct='%1.1f%%')
            ax2.set_title('Composition')
            st.pyplot(fig2)

    st.subheader(tr(lang_choice, "scenarios_header"))
    if st.button(tr(lang_choice, "show_crack_times")):
        sample_pw = st.session_state.get('gen_pass', 'Tr0ub4dor!')
        rows = []
        ks_s, cs_s, _ = detect_charset_size(sample_pw)
        for name, speed in [
            ('Online (10/sec)', 10),
            ('Slow hash (100/sec)', 100),
            ('Moderate GPU (1e7/sec)', 1e7),
            ('High-end GPU (1e9/sec)', 1e9),
        ]:
            t = estimate_bruteforce_time(ks_s, speed, average=True)
            rows.append({tr(lang_choice,'scenario'): name, tr(lang_choice,'time'): pretty_time(t)})
        st.table(pd.DataFrame(rows))

# ========================= History & Export Tab =========================
with tab_history:
    st.header(tr(lang_choice, 'history_header'))
    if st.session_state.history:
        df_hist = pd.DataFrame(st.session_state.history)
        st.dataframe(df_hist)
        csv = df_hist.to_csv(index=False).encode('utf-8')
        st.download_button(tr(lang_choice,'download_csv'), data=csv, file_name='password_analysis_history.csv', mime='text/csv')
        if st.button(tr(lang_choice,'clear_history')):
            st.session_state.history = []
            st.rerun()
    else:
        st.info(tr(lang_choice,'no_history'))

    st.header(tr(lang_choice, 'export_header'))
    if st.button(tr(lang_choice, 'generate_pdf')):
        pw = None
        if 'gen_pass' in st.session_state and st.session_state.gen_pass:
            pw = st.session_state.gen_pass
        elif 'last_password_raw' in st.session_state:
            pw = st.session_state.last_password_raw
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
            _, hash_time = hash_simulation(pw, algo='sha256', bcrypt_rounds=bcrypt_rounds)
            pdf_bytes = make_pdf_report(lang_choice, pw, score, ks_val, cs, Hk, Hs, breached, bf_avg, bf_worst, dict_t, dict_hit, hyb_t, 'sha256', hash_time)
            st.download_button(tr(lang_choice,'download_pdf'), data=pdf_bytes, file_name='password_report_extended.pdf', mime='application/pdf')
        else:
            st.warning(tr(lang_choice,'no_pass_for_pdf'))

# ========================= About Tab =========================
with tab_about:
    st.header(tr(lang_choice, "whats_new"))
    st.markdown(tr(lang_choice, "whats_new_points"))
    st.caption(tr(lang_choice, 'footer'))



