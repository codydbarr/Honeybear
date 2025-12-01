#for processing data srouce
import numpy as np
import pandas as pd
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

#for ML models
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import IsolationForest #anomaly detection

#for API exposure/handling 
from flask import Flask, request, jsonify

#global variables, mostly the models
app = Flask(__name__)
log_reg = LogisticRegression(penalty='l2', C=0.01, max_iter=5000)
tree_ent = DecisionTreeClassifier(criterion = "entropy", random_state = 10, max_depth=6, min_samples_leaf=5)
rf = RandomForestClassifier(n_estimators=200, max_depth=10, min_samples_leaf=5, random_state=10, class_weight='balanced')
ada = AdaBoostClassifier(estimator=tree_ent, n_estimators=50, learning_rate=0.1, random_state=10)
clf = IsolationForest(
    n_estimators=200,      # number of trees
    max_samples="auto",    # subsample size for each tree
    contamination=0.06,    # expected proportion of outliers
    max_features=1.0,      # number of features per split
    bootstrap=False,       # whether to bootstrap samples
    random_state=10        # reproducibility
)

def get_dataset():
    df = pd.read_csv('honeypot_final.csv')
    # Select columns
    x_labels1 = df.columns[list(range(6, 55))]
    X = df[x_labels1].copy()   # keep as DataFrame for easier manipulation
    # Label encode just the first column in x_labels1
    le = LabelEncoder()
    X.iloc[:, 0] = le.fit_transform(X.iloc[:, 0])

    # Convert to numpy array if needed
    X = np.array(X.values)
    y = df['isHoneypot'].values
    return X, y


def get_classification(model, record):
    classification=model.predict(record)
    probability=model.predict_proba(record)[:, 1]
    if classification==1:
        label="Honeypot"
    else:
        label="Not a Honeypot"
    return label, classification, probability

def get_anomaly(model, record):
    classification=model.predict(record)
    score=model.decision_function(record)
    if classification<0:
        label="Anomaly"
    else:
        label="Not an Anomaly"
    return label, classification, score

def process_post(data):
    df = pd.DataFrame([data])
    x_labels1 = df.columns[list(range(0, 49))]
    X = df[x_labels1].copy()   # keep as DataFrame for easier manipulation
    X = np.array(X.values)
    return X
    

# Define a POST endpoint
@app.route('/api/data', methods=['POST'])
def receive_data():
    print("here")
    # Ensure the request contains JSON
    if not request.is_json:
        return jsonify({"error": "Invalid input, expected JSON"}), 400

    # Parse the JSON payload
    data = request.get_json()

    #Process the received json into a useable format for the models
    X = process_post(data)

    #Call proper methods for each model
    if 'model' in data:
       model=data['model']
       if model=='anomaly':
           label, classification, score=get_anomaly(clf, X)
       elif model=='logreg':
           label, classification, prob=get_classification(log_reg, X)
       elif model=='randforest':
           label, classification, prob=get_classification(rf, X)
       elif model=='ada':
           label, classification, prob=get_classification(ada, X)

       #Format output
       if model=='anomaly':
            response = {
                "message": "Data received successfully",
                "model": model,
                "label": label,
                "Classification": classification[0].tolist(),
                "Score": score[0].tolist()
            }
       else:
            response = {
                "message": "Data received successfully",
                "model": model,
                "label": label,
                "Classification": classification[0].tolist(),
                "Probability": prob[0].tolist()
            }
    return jsonify(response), 200




if __name__ == '__main__':
    #Prepare dataset for training
    X, y=get_dataset()

    #Train each model
    log_reg.fit(X, y)
    tree_ent.fit(X, y)
    rf.fit(X, y)
    ada.fit(X, y)
    clf.fit(X)

    #Listen for incoming requests    
    app.run(debug=True, host="127.0.0.1", port=4001)
