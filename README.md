# Phishing URL Detector 🔐

A machine learning model that detects phishing URLs with 97.38% accuracy.

## Results
| Model | Accuracy | AUC |
|---|---|---|
| Logistic Regression | 93.89% | - |
| Random Forest | 97.38% | 0.9947 |

## Key Findings
- HTTPS usage and Anchor URLs were the strongest phishing signals
- Model catches 96% of all phishing sites with 98% precision
- Only 58 mistakes out of 2,211 test URLs

## Tech Stack
Python, Scikit-learn, Pandas, Matplotlib, Seaborn

## How to Run
1. Clone the repo
2. pip install pandas numpy matplotlib seaborn scikit-learn
3. Open notebooks/phishing_url_detector.ipynb
4. Run all cells
