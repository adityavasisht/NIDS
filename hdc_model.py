import numpy as np

class HDClassifier:
    def __init__(self, dimensions=10000, random_state=42):
        self.dimensions = dimensions
        self.random_state = random_state
        self.base_vectors = None
        self.class_hypervectors = {}
        self.classes_ = []

    def _encode(self, X):
        if self.base_vectors is None:
            np.random.seed(self.random_state)
            self.base_vectors = np.random.choice([-1, 1], size=(X.shape[1], self.dimensions))
        projection = np.dot(X, self.base_vectors)
        return np.where(projection >= 0, 1, -1)

    def fit(self, X, y):
        encoded_X = self._encode(X)
        self.classes_ = np.unique(y)
        for c in self.classes_:
            class_samples = encoded_X[y == c]
            summed = np.sum(class_samples, axis=0)
            self.class_hypervectors[c] = np.where(summed >= 0, 1, -1)
        return self

    def predict_proba(self, X):
        encoded_X = self._encode(X)
        probas = []
        norms_cv = {c: np.linalg.norm(self.class_hypervectors[c]) for c in self.classes_}
        for sample in encoded_X:
            sample_norm = np.linalg.norm(sample)
            sims = []
            for c in self.classes_:
                sim = np.dot(sample, self.class_hypervectors[c]) / (sample_norm * norms_cv[c]) if sample_norm > 0 else 0
                sims.append(sim + 1.0)
            probas.append(np.array(sims) / np.sum(sims))
        return np.array(probas)