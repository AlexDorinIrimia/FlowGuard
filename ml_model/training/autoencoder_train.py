import numpy as np
from ml_model.models import Autoencoder

class AutoencoderTrainer:
    def __init__(self, input_dim):
        self.model_builder = Autoencoder(input_dim)
        self.model = self.model_builder.build()

    def train(self,X_train, epochs=20, batch_size=32):
        self.model.fit(X_train, X_train,
                       epochs=epochs,
                       batch_size=batch_size,
                       shuffle=True,
                       validation_split=0.1)

    def save_model(self, path):
        self.model.save(path)


