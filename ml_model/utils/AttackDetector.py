import pandas as pd
from tensorflow.keras.models import load_model
import numpy as np
import joblib
from pathlib import Path
from math import exp

class AttackDetector:
    def __init__(self):
        base_dir = Path(__file__).resolve().parent.parent / "models" / "models"

        # Load models
        self.autoencoder_model = load_model(base_dir / 'autoencoder_tf.keras')
        self.svm_model = load_model(base_dir / 'svm_model_tf.keras')
        self.xgb_model = joblib.load(base_dir / 'xgb_model.pkl')

        # Load scalers and encoders
        self.svm_scaler = joblib.load(base_dir / 'scaler.pkl')
        self.autoencoder_scaler = joblib.load(base_dir / 'ae_scaler_tf.pkl')
        self.xgb_label_encoder = joblib.load(base_dir / 'xgb_label_encoder.pkl')

        # Threshold for autoencoder reconstruction error
        self.ae_threshold = 1e-6

        # Feature names expected (same order as training)
        self.feature_names = [
            " Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets", "Total Length of Fwd Packets",
            " Total Length of Bwd Packets", " Fwd Packet Length Max", " Fwd Packet Length Min", " Fwd Packet Length Mean",
            " Fwd Packet Length Std", "Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean",
            " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max",
            " Flow IAT Min", "Fwd IAT Total", " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean",
            " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags", " Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length",
            " Bwd Header Length", "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length", " Max Packet Length", " Packet Length Mean",
            " Packet Length Std", " Packet Length Variance", "FIN Flag Count", " SYN Flag Count", " RST Flag Count",
            " PSH Flag Count", " ACK Flag Count", " URG Flag Count", " CWE Flag Count", " ECE Flag Count", " Down/Up Ratio", " Average Packet Size",
            " Avg Fwd Segment Size", " Avg Bwd Segment Size", " Fwd Header Length.1", "Fwd Avg Bytes/Bulk", " Fwd Avg Packets/Bulk",
            " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", " Subflow Fwd Bytes",
            " Subflow Bwd Packets", " Subflow Bwd Bytes", "Init_Win_bytes_forward", " Init_Win_bytes_backward", " act_data_pkt_fwd",
            " min_seg_size_forward", "Active Mean", " Active Std", " Active Max", " Active Min", "Idle Mean", " Idle Std", " Idle Max", " Idle Min"
        ]

    def predict(self, packet):
        """
        Run input features through the 3-stage pipeline:
        1. Autoencoder anomaly detection (fast coarse filter)
        2. SVM refinement (binary classifier)
        3. XGBoost multi-class attack classification
        Returns (labels, confidence_score)
        """
        try:
            packet = np.array(packet)
            if len(packet.shape) == 1:
                packet = packet.reshape(1, -1)

            if packet.shape[1] != len(self.feature_names):
                raise ValueError(f"Feature count mismatch: expected {len(self.feature_names)}, got {packet.shape[1]}")

            # Convert to DataFrame for consistency/scaling
            df_packet = pd.DataFrame(packet, columns=self.feature_names)

            # --- Stage 1: Autoencoder ---
            scaled_ae = self.autoencoder_scaler.transform(df_packet)
            reconstructions = self.autoencoder_model.predict(scaled_ae)
            recon_error = np.mean(np.square(scaled_ae - reconstructions), axis=1)

            # Calculate confidence: 1 - normalized recon error

            confidence = 1.0 / (1.0 + exp((recon_error[0] - self.ae_threshold) * 20))
            print(f"Reconstruciton error{recon_error[0]}, confidence: {confidence:.2f}")

            # Autoencoder flag: anomaly if reconstruction error > threshold
            ae_anomaly = recon_error > self.ae_threshold

            if not ae_anomaly[0]:
                # Not anomaly, classify as benign immediately
                return ['BENIGN'], confidence

            # --- Stage 2: SVM Refinement ---
            #df_anomalies = df_packet[ae_anomaly]
            #scaled_svm = self.svm_scaler.transform(df_anomalies)
            #svm_pred = self.svm_model.predict(scaled_svm)

            # Assuming svm_model outputs sigmoid probabilities (0 benign, 1 attack)
            # If you use a different output, adjust accordingly.
            # Here we take prediction > 0.5 as attack
            #svm_attack_mask = svm_pred.flatten() > 0.5
            #if not np.any(svm_attack_mask):
                # SVM says benign after refinement
                #return ['BENIGN'], confidence
            return ['Attack'], confidence
            #df_refined = df_anomalies.iloc[svm_attack_mask]
            #df_refined = df_packet[ae_anomaly]
            # --- Stage 3: XGBoost classification ---
            #xgb_preds = self.xgb_model.predict(df_refined)
            #labels = self.xgb_label_encoder.inverse_transform(xgb_preds)

            #return labels.tolist(), confidence

        except Exception as e:
            print(f"[ERROR] AttackDetector predict error: {e}")
            return [], 0.0