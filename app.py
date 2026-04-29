import streamlit as st
import joblib
import pandas as pd
import re
import urllib.parse

st.set_page_config(page_title="Phishing URL Detector", page_icon="🔍", layout="centered")

@st.cache_resource
def load_model():
    return joblib.load("phishing_model.pkl")

model = load_model()

FEATURE_COLS = [
    'UsingIP','LongURL','ShortURL','Symbol@','Redirecting//','PrefixSuffix-',
    'SubDomains','HTTPS','DomainRegLen','Favicon','NonStdPort','HTTPSDomainURL',
    'RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler','InfoEmail',
    'AbnormalURL','WebsiteForwarding','StatusBarCust','DisableRightClick',
    'UsingPopupWindow','IframeRedirection','AgeofDomain','DNSRecording',
    'WebsiteTraffic','PageRank','GoogleIndex','LinksPointingToPage','StatsReport'
]

FEATURE_LABELS = {
    'UsingIP': 'IP Address as Domain',
    'LongURL': 'Suspicious URL Length (>75 chars)',
    'ShortURL': 'URL Shortening Service',
    'Symbol@': '@ Symbol in URL',
    'Redirecting//': 'Double Slash Redirect in Path',
    'PrefixSuffix-': 'Hyphen in Domain Name',
    'SubDomains': 'Excessive Subdomains (3+)',
    'HTTPS': 'No HTTPS (insecure connection)',
    'DomainRegLen': 'Suspicious Domain Length',
    'NonStdPort': 'Non-standard Port',
    'HTTPSDomainURL': "'https' Token Embedded in Domain",
    'InfoEmail': 'Mailto Link in URL',
    'AbnormalURL': 'Missing Domain',
    'WebsiteForwarding': 'Multiple HTTP Occurrences (forwarding)',
}

SHORTENERS = [
    'bit.ly','tinyurl.com','goo.gl','ow.ly','t.co','is.gd',
    'adf.ly','tiny.cc','cutt.ly','rebrand.ly','short.link','buff.ly'
]

def analyse_url(url):
    url = url.strip()
    try:
        parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
    except Exception:
        parsed = urllib.parse.urlparse('')
    domain   = parsed.netloc.split(':')[0] if parsed.netloc else ''
    path     = parsed.path or ''
    full_url = url.lower()
    scheme   = parsed.scheme.lower()

    def ph(c): return -1 if c else 1   # condition = phishing indicator
    def lg(c): return 1 if c else -1   # condition = legit indicator

    # Hard rule flags (definitive structural signals)
    hard_flags = {}
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', domain):
        hard_flags['UsingIP'] = 'IP address used as domain'
    if '@' in url:
        hard_flags['Symbol@'] = '@ symbol in URL'
    if any(s in domain for s in SHORTENERS):
        hard_flags['ShortURL'] = 'URL shortening service detected'
    if full_url.count('http') > 1:
        hard_flags['WebsiteForwarding'] = 'Multiple HTTP in URL'

    features = {
        'UsingIP':           ph(bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', domain))),
        'LongURL':           ph(len(url) > 75),
        'ShortURL':          ph(any(s in domain for s in SHORTENERS)),
        'Symbol@':           ph('@' in url),
        'Redirecting//':     ph('//' in path),
        'PrefixSuffix-':     ph('-' in domain),
        'SubDomains':        ph(domain.count('.') > 2),
        'HTTPS':             lg(scheme == 'https'),
        'DomainRegLen':      lg(len(domain) >= 12),
        'Favicon':           1,
        'NonStdPort':        ph(parsed.port not in (None, 80, 443)),
        'HTTPSDomainURL':    ph('https' in domain and scheme != 'https'),
        'RequestURL':        0,
        'AnchorURL':         ph(bool(parsed.fragment)),
        'LinksInScriptTags': 0,
        'ServerFormHandler': 0,
        'InfoEmail':         ph('mailto:' in full_url),
        'AbnormalURL':       ph(domain == ''),
        'WebsiteForwarding': ph(full_url.count('http') > 1),
        'StatusBarCust':     0, 'DisableRightClick': 0, 'UsingPopupWindow': 0,
        'IframeRedirection': 0, 'AgeofDomain':       0, 'DNSRecording':     0,
        'WebsiteTraffic':    1, 'PageRank':           0, 'GoogleIndex':      1,
        'LinksPointingToPage': 0, 'StatsReport':      1,
    }

    df_feat  = pd.DataFrame([features], columns=FEATURE_COLS)
    pred     = model.predict(df_feat)[0]
    proba    = model.predict_proba(df_feat)[0]
    classes  = list(model.classes_)
    phish_p  = proba[classes.index(-1)] * 100
    legit_p  = proba[classes.index(1)]  * 100

    # Override: hard flags always win
    final = -1 if hard_flags else pred
    return final, phish_p, legit_p, hard_flags, features

# ── UI ─────────────────────────────────────────────────────────────────────────
st.title("🔍 Phishing URL Detector")
st.markdown(
    "Enter any URL and the model will classify it using **13 structural URL features** "
    "combined with rule-based checks for high-confidence signals."
)
st.markdown("---")

url_input = st.text_input(
    "Enter a URL to analyse",
    placeholder="e.g. https://www.google.com",
)

c1, c2, c3 = st.columns([1.5, 1, 1.5])
with c2:
    run = st.button("🔎 Analyse", use_container_width=True)

if run:
    if not url_input.strip():
        st.warning("Please enter a URL first.")
    else:
        with st.spinner("Analysing..."):
            pred, phish_p, legit_p, hard_flags, features = analyse_url(url_input)

        st.markdown("---")

        if pred == -1:
            st.error("## ⚠️ Phishing URL Detected")
            if hard_flags:
                st.markdown("**Definitive signals found:**")
                for msg in hard_flags.values():
                    st.markdown(f"- 🚩 {msg}")
            st.markdown("Do **not** enter credentials or personal information on this site.")
        else:
            st.success("## ✅ Looks Legitimate")
            st.markdown("No strong phishing indicators detected in the URL structure.")

        st.markdown("### Model Confidence")
        ca, cb = st.columns(2)
        with ca:
            st.metric("🎣 Phishing", f"{phish_p:.1f}%")
            st.progress(phish_p / 100)
        with cb:
            st.metric("✅ Legitimate", f"{legit_p:.1f}%")
            st.progress(legit_p / 100)

        with st.expander("🔬 Feature breakdown"):
            labels_map = {-1: "🔴 Phishing signal", 1: "🟢 Legit signal", 0: "⚪ Unknown (not extractable)"}
            rows = []
            for feat, label in FEATURE_LABELS.items():
                val = features.get(feat, 0)
                rows.append({"Feature": label, "Signal": labels_map.get(int(val), "⚪")})
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            st.caption(
                "Features marked ⚪ Unknown require fetching the page content (e.g. anchor links, "
                "script tags, page rank) and cannot be determined from URL structure alone."
            )

        st.markdown("---")
        st.caption(
            "⚠️ Analyses URL structure only — no page content or DNS lookups. "
            "Model trained on 11,054 URLs with 96.9% test accuracy. "
            "Not a substitute for professional security tools."
        )

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 📖 About")
    st.markdown(
        "Built by **Nilkanth Changawala** using a **Random Forest classifier** "
        "trained on 11,054 URLs.\n\n"
        "**Model accuracy: 96.9%**\n\n"
        "Combines ML prediction with rule-based checks for IP addresses, "
        "URL shorteners, @ symbols, and forwarding patterns."
    )
    st.markdown("---")
    st.markdown("### 🔗 Links")
    st.markdown(
        "[GitHub](https://github.com/Nilkanth29/Phishing-URL_detector)  |  "
        "[LinkedIn](https://www.linkedin.com/in/nilkanth-changawala/)"
    )
    st.markdown("---")
    st.markdown("### ⚡ Test URLs")
    st.markdown("**Likely Legitimate:**")
    st.code("https://www.google.com")
    st.code("https://www.anz.com.au/personal")
    st.markdown("**Likely Phishing:**")
    st.code("http://192.168.1.1/secure/login")
    st.code("http://paypal-secure@evil.tk/verify")
    st.code("http://bit.ly/free-prize-claim")
    st.code("http://www.paypal.com-secure.tk/account")
