from sklearn import svm

class SVM:
    def __init__(self):
        self.model = svm.OneClassSVM(kernel='rbf', gamma='auto', nu=0.01)

    def get_model(self):
        return self.model

