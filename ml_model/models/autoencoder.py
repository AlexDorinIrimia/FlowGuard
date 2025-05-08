import tensorflow as tf

class Autoencoder:
    def __init__(self, input_dim):
        self.input_dim = input_dim

    def build(self):
        inputs = tf.keras.layers.Input(shape=self.input_dim)
        encoded = tf.keras.layers.Dense(64, activation='relu')(inputs)
        encoded = tf.keras.layers.Dense(32, activation='relu')(encoded)
        decoded = tf.keras.layers.Dense(64, activation='relu')(encoded)
        outputs = tf.keras.layers.Dense(self.input_dim, activation='sigmoid')(decoded)

        model = tf.keras.Model(inputs, outputs)
        model.compile(optimizer='adam', loss='mse')

        return model