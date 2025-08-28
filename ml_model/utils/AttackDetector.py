import numpy as np
import pandas as pd
from pathlib import Path
import tensorflow as tf
from tensorflow.keras.models import load_model, Model
import joblib
from tensorflow.keras.losses import Huber
from backend.packet_capture.Flow import Flow

class AttackDetector:

    def __init__(self):
        root = Path(__file__).resolve().parent.parent / "models" / "models"

        # ── Autoencoder & SVM ─────────────────────────────
        self.autoencoder = load_model(root / "autoencoder_optimal_tf.keras")
        self.encoder = self.create_encoder()
        self.svm = joblib.load(root / "linearsvc_calibrated_smote_with_threshold.pkl")

        # ── Scaler & label encoder (legacy flat model) ──
        self.scaler_78 = joblib.load(root / "ae_scaler_optimal.pkl")

        # ── Threshold & feature tracking ────────────────
        self.ae_thr = 0.001417
        self.feature_names = [...]  # lista ta de 27 feature-uri
        self.huber_loss = Huber(delta=0.5, reduction='none')

    def create_encoder(self):
        inputs = tf.keras.Input(shape=(27,))
        x = inputs
        for i in range(10):
            x = self.autoencoder.layers[i](x)
        encoder = Model(inputs=inputs, outputs=x)
        return encoder

    def ae_confidence(self, re_error, mean=3.446036e-03, std=8.923405e-03):
        if std == 0:
            return 1.0 if re_error <= mean else 0.0
        z = (re_error - mean) / std
        conf = 1 / (1 + np.exp(-5 * (z)))  # coef 5 pentru a face sigmoid mai abrupt
        return float(conf)

    def compute_confidence(self, ae_conf, svm_conf):
        return 0.4 * ae_conf + 0.6 * svm_conf

    def predict(self, flow: Flow):
        try:
            # ── Extract & scale raw features ─────────
            feat_vec = flow.extract_features()
            pkt = np.asarray(feat_vec, dtype=np.float32).reshape(1, -1)
            if pkt.shape[1] != 27:
                raise ValueError(f"Expected 27 raw features, got {pkt.shape[1]}")

            df_scaled = self.scaler_78.transform(pd.DataFrame(pkt))

            # ── Autoencoder reconstruction error ────
            recon = self.autoencoder.predict(df_scaled, verbose=0)
            err_tensor = self.huber_loss(
                tf.convert_to_tensor(df_scaled, dtype=tf.float32),
                tf.convert_to_tensor(recon, dtype=tf.float32)
            )
            err = float(tf.reduce_mean(err_tensor).numpy())
            print(f"AE error: {err}")
            conf_ae = self.ae_confidence(err)
            if err < self.ae_thr:
                return ['BENIGN'], conf_ae

            # ── Encode latent features ───────────────
            latent = self.encoder.predict(df_scaled, verbose=0)

            # ── SVM binary check ─────────────────────
            prob_attack = self.svm['model'].predict_proba(latent)[0, 1]
            print(f"SVM prob: {prob_attack}")
            conf = self.compute_confidence(conf_ae, prob_attack)
            print(f"Confidence: {conf}")
            if conf > 0.7:
                return ["ATTACK"], conf
            else:
                return ['BENIGN'], 1 - conf

        except Exception as ex:
            print(f"Prediction error:\n{ex}")
            return ['UNKNOWN'], 0.0
