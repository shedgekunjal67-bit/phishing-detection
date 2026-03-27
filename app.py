from flask import Flask, request, jsonify
import pickle
from feature_extractor import extract_features
from utils.api_checker import check_phishstats

app = Flask(__name__)

# Load trained model
model = pickle.load(open("phishing_model.pkl", "rb"))


@app.route('/')
def home():
    return "Phishing Detection API is running!"


@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get URL from request
        url = request.form.get('url') or request.json.get('url')

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # 🔹 STEP 1: Check PhishStats Blacklist
        if check_phishstats(url):
            return jsonify({
                "url": url,
                "status": "malicious",
                "source": "PhishStats Blacklist"
            })

        # 🔹 STEP 2: ML Model Prediction
        features = extract_features(url)
        prediction = model.predict([features])[0]

        result = "malicious" if prediction == 1 else "safe"

        return jsonify({
            "url": url,
            "status": result,
            "source": "ML Model"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
