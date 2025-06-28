import numpy as np
import pandas as pd
from pathlib import Path
import tensorflow as tf
from tensorflow.keras.models import load_model, Model
import xgboost as xgb
import joblib
from backend.logging.logger import IDSLogger


def hybrid_loss(y_true, y_pred):
    mse = tf.reduce_mean(tf.square(y_true - y_pred), axis=-1)
    mae = tf.reduce_mean(tf.abs(y_true - y_pred), axis=-1)
    return 0.7 * mse + 0.3 * mae

class AttackDetector:

    def __init__(self):
        root = Path(__file__).resolve().parent.parent / "models" / "models"

        # ── Load models ─────────────────────────────────────────────
        self.autoencoder = load_model(root / "autoencoder_tf.keras", custom_objects={'hybrid_loss':hybrid_loss})
        self.encoder = self.create_encoder()
        self.svm = joblib.load(root / "svm_calibrated.pkl")  # CalibratedClassifierCV
        self.xgb = xgb.Booster()
        self.xgb.load_model(root / "xgb_attack_only.json")

        # ── Load scalers / encoders ────────────────────────────────
        self.scaler_78 = joblib.load(root / "ae_scaler_tf.pkl")
        self.label_enc = joblib.load(root / "label_encoder_attack_only.pkl")

        # ── Autoencoder anomaly threshold ───────────────────────────
        self.ae_thr = 0.004841903

        # ── Feature name tracking ───────────────────────────────────
        self.feature_names = [
            " Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
            "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max",
            " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std", "Bwd Packet Length Max",
            " Bwd Packet Length Min", " Bwd Packet Length Mean", " Bwd Packet Length Std", "Flow Bytes/s",
            " Flow Packets/s", " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total",
            " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean",
            " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags", " Bwd PSH Flags", " Fwd URG Flags",
            " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length", "Fwd Packets/s", " Bwd Packets/s",
            " Min Packet Length", " Max Packet Length", " Packet Length Mean", " Packet Length Std",
            " Packet Length Variance", "FIN Flag Count", " SYN Flag Count", " RST Flag Count", " PSH Flag Count",
            " ACK Flag Count", " URG Flag Count", " CWE Flag Count", " ECE Flag Count", " Down/Up Ratio",
            " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size", " Fwd Header Length.1",
            "Fwd Avg Bytes/Bulk", " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk",
            " Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", " Subflow Fwd Bytes",
            " Subflow Bwd Packets", " Subflow Bwd Bytes", "Init_Win_bytes_forward", " Init_Win_bytes_backward",
            " act_data_pkt_fwd", " min_seg_size_forward", "Active Mean", " Active Std", " Active Max", " Active Min",
            "Idle Mean", " Idle Std", " Idle Max", " Idle Min"
        ]
        self.latent_dim = 8
        self.latent_feature_names = [f"latent_{i}" for i in range(self.latent_dim)]
        self.features_87_names = self.feature_names + self.latent_feature_names + ["error"]

        self.logger = IDSLogger()

    def create_encoder(self):
        inputs = tf.keras.Input(shape=(78,))
        x = inputs
        for layer in self.autoencoder.layers[1:8]:
            x = layer(x)

        return Model(inputs, x)
    def _ae_conf(self, err):
        max_err = 0.01  # Adjust based on your validation data
        if err <= self.ae_thr:
            return 0.0
        conf = (err - self.ae_thr) / (max_err - self.ae_thr)
        return min(max(conf, 0.0), 1.0)

    def _combine_confidences(self, conf_ae, prob_svm, conf_xgb, label_xgb):
        xgb_weight = 0.2 if label_xgb != "BENIGN" else 0.1
        weights = {"ae": 0.25, "svm": 0.55, "xgb": xgb_weight}
        total_weight = sum(weights.values())
        for k in weights:
            weights[k] /= total_weight
        combined = (
                conf_ae * weights["ae"] +
                prob_svm * weights["svm"] +
                conf_xgb * weights["xgb"]
        )
        return round(combined, 4)

    def predict(self, feat_vec):
        try:
            pkt = np.asarray(feat_vec, dtype=np.float32).reshape(1, -1)
            if pkt.shape[1] != 78:
                raise ValueError(f"Expected 78 raw features, got {pkt.shape[1]}")

            # Scale raw features
            df_raw = pd.DataFrame(pkt, columns=self.feature_names)
            X78_scaled = self.scaler_78.transform(df_raw)

            # Autoencoder reconstruction and error
            recon = self.autoencoder.predict(X78_scaled, verbose=0)
            err_tensor = hybrid_loss(
                tf.convert_to_tensor(X78_scaled, dtype=tf.float32),
                tf.convert_to_tensor(recon, dtype=tf.float32)
            )
            err = float(err_tensor.numpy())
            conf_ae = self._ae_conf(err)

            # Early exit if benign
            if err <= self.ae_thr:
                return ['BENIGN'], round(conf_ae, 4)

            # Extract latent + combine features
            latent = self.encoder.predict(X78_scaled, verbose=0)
            X87 = np.hstack([X78_scaled, latent, [[err]]])

            # SVM stage
            prob_attack = self.svm.predict_proba(X87)[0, 1]
            if prob_attack < 0.6:  # consider tuning threshold here
                return ['BENIGN'], round(conf_ae * (1 - prob_attack), 4)

            # XGBoost final classification
            dmat = xgb.DMatrix(X87)
            probs = self.xgb.predict(dmat)[0]
            top_idx = int(np.argmax(probs))
            label = self.label_enc.inverse_transform([top_idx])[0]
            xgb_conf = probs[top_idx]

            # Combined confidence score
            conf_final = round(conf_ae * prob_attack * xgb_conf, 4)
            if label != 'BENIGN' and conf_final >= 0.7:
                return [label], conf_final
            else:
                return ["BENIGN"], 0.0

        except Exception as ex:
            self.logger.get_logger().error(f"Prediction error: {ex}", exc_info=True)
            return ['UNKNOWN'], 0.0
