import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score
from hdc_model import HDClassifier

# NSL-KDD standard column names (41 features + label + difficulty)
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 
    'label', 'difficulty'
]

def load_data(filepath):
    df = pd.read_csv(filepath, names=COLUMNS)
    # Map all specific attacks to 'anomaly' to create a binary classification task
    df['label'] = df['label'].apply(lambda x: 'normal' if x == 'normal' else 'anomaly')
    X = df.iloc[:, :-2] # Drop label and difficulty
    y = df['label']
    return X, y

if __name__ == "__main__":
    print("Loading KDDTrain+.txt and KDDTest+.txt...")
    X_train, y_train = load_data('KDDTrain+.txt')
    X_test, y_test = load_data('KDDTest+.txt')

    # 1. Define Preprocessing Pipeline
    categorical_cols = ['protocol_type', 'service', 'flag']
    numerical_cols = [c for c in X_train.columns if c not in categorical_cols]

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_cols),
            ('cat', OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1), categorical_cols)
        ])

    print("Fitting preprocessor and transforming data...")
    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)
    
    feature_names = numerical_cols + categorical_cols

    # 2. Feature Selection via Random Forest
    print("Training initial RandomForest to extract top 20 features...")
    selector_rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    selector_rf.fit(X_train_processed, y_train)

    importances = selector_rf.feature_importances_
    top_20_indices = np.argsort(importances)[-20:][::-1]
    top_20_features = [feature_names[i] for i in top_20_indices]
    
    print(f"Top 20 Features selected: {top_20_features}")

    # Subset data to top 20 features
    X_train_top20 = X_train_processed[:, top_20_indices]
    X_test_top20 = X_test_processed[:, top_20_indices]

    # 3. Train Ensemble Models
    print("Training Custom HDClassifier...")
    hdc = HDClassifier(dimensions=10000)
    hdc.fit(X_train_top20, y_train)

    print("Training Final RandomForestClassifier...")
    rf_final = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_final.fit(X_train_top20, y_train)

    # 4. Custom Soft Voting Evaluation
    print("Evaluating Ensemble with Custom Soft Voting...")
    rf_probas = rf_final.predict_proba(X_test_top20)
    hdc_probas = hdc.predict_proba(X_test_top20)
    
    # Soft voting: average the probabilities
    ensemble_probas = (rf_probas + hdc_probas) / 2
    
    classes = rf_final.classes_ # ['anomaly', 'normal']
    y_pred = classes[np.argmax(ensemble_probas, axis=1)]
    
    acc = accuracy_score(y_test, y_pred)
    print(f"Ensemble Accuracy on KDDTest+: {acc * 100:.2f}%")

    # 5. Export the complete state
    print("Exporting pipeline to optimized_ensemble.joblib...")
    export_data = {
        'preprocessor': preprocessor,
        'feature_names_ordered': feature_names,
        'top_20_indices': top_20_indices,
        'top_20_features': top_20_features,
        'rf_model': rf_final,
        'hdc_model': hdc,
        'classes': classes
    }
    joblib.dump(export_data, 'optimized_ensemble.joblib')
    print("Export complete.")