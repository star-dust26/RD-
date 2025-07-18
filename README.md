# RD-
Internship 
# 1. Malware Detection System
   
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pandas as pd

df = pd.read_csv("malware_dataset.csv")  # Columns: feature1, feature2, ..., label

X = df.drop("label", axis=1)
y = df["label"]  # 1 = malware, 0 = benign

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# 2. Phishing URL Detection

from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pandas as pd

df = pd.read_csv("phishing_urls.csv")  # Columns: url, label (0=legit, 1=phish)

vectorizer = CountVectorizer()
X = vectorizer.fit_transform(df["url"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
model = LogisticRegression()
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# 3.Anomaly Detection in Network Traffic 

from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("network_traffic.csv")  # Numeric network stats per row

scaler = StandardScaler()
X = scaler.fit_transform(df)

kmeans = KMeans(n_clusters=2)  # Assuming two clusters: normal & anomaly
labels = kmeans.fit_predict(X)

df['anomaly'] = labels
print(df.head())

# 4.Password Strength Evaluator 

import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def extract_features(password):
    return [
        len(password),
        len(set(password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[!@#$%^&*()]", password))
    ]

data = [
    ("12345", 0), ("Password1", 1), ("S#perS3cur3!", 2),
]

X = [extract_features(pw) for pw, _ in data]
y = [label for _, label in data]

clf = RandomForestClassifier()
clf.fit(X, y)

test_pw = "MyStr0ngP@ssword"
print("Strength:", clf.predict([extract_features(test_pw)]))


