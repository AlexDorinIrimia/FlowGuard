import joblib
from ml_model.models import SVM

class SVMTrainer:
    def __init__(self):
        self.model = SVM.get_model()

    def train(self, X_train, y_train):
        self.train(X_train, y_train)

    def save_model(self, filename):
        joblib.dump(self.model, filename)