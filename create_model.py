import pickle
from sklearn.ensemble import RandomForestClassifier

X = [
    [20, 1, 2, 0, 0],
    [100, 0, 5, 1, 1],
]
y = [0, 1]

model = RandomForestClassifier()
model.fit(X, y)

pickle.dump(model, open("phishing_model.pkl", "wb"))

print("Model created!")
