# Phishing URL Detector — Streamlit App

A machine learning web app that detects phishing URLs using a Random Forest classifier trained on 11,054 URLs with 96.9% accuracy.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Cloud (free)

1. Push this folder to a GitHub repo
2. Go to https://share.streamlit.io
3. Connect your GitHub repo
4. Set main file path to `app.py`
5. Click Deploy

## Project Structure

```
├── app.py                  # Streamlit app
├── phishing_model.pkl      # Trained Random Forest model
├── requirements.txt        # Dependencies
└── README.md
```

## Model Details

- **Algorithm:** Random Forest (100 estimators)
- **Training data:** 11,054 URLs (6,157 legitimate, 4,897 phishing)
- **Features:** 30 URL-based features (IP usage, URL length, HTTPS, subdomains, etc.)
- **Accuracy:** 96.9% on held-out test set

## Built by

Nilkanth Changawala | [LinkedIn](https://www.linkedin.com/in/nilkanth-changawala/) | [GitHub](https://github.com/Nilkanth29)
