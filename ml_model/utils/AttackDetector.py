from tensorflow.keras.models import load_model
import numpy as np
import joblib
from pathlib import Path

class AttackDetector:
    def __init__(self):
        base_dir = Path(__file__).resolve().parent.parent / "models" / "models"

        self.autoencoder_model = load_model(base_dir/'autoencoder_tf.keras')
        self.svm_model = load_model(base_dir/'svm_model_tf.keras')
        self.xgb_model = joblib.load(base_dir/'xgb_model.pkl')
        self.svm_scaler = joblib.load(base_dir/'scaler.pkl')
        self.autoencoder_scaler = joblib.load(base_dir/'ae_scaler_tf.pkl')
        self.xgb_label_encoder = joblib.load(base_dir/'xgb_label_encoder.pkl')
        self.ae_threshold = 0.0001

    def predict(self, packet):
        try:
            # Convert input to numpy array if it isn't already
            return self._predict_internal(packet)
        except Exception as e:
            print(f"Error in predict method: {str(e)}")
            return [], 0.0

    def _predict_internal(self, packet):
        packet = np.array(packet)
        if len(packet.shape) == 1:
            packet = packet.reshape(1, -1)
        
        # Step 1: Scale the input for autoencoder
        packet_scaled_ae = self.autoencoder_scaler.transform(packet)
        
        # Step 2: Autoencoder reconstruction error
        reconstructions = self.autoencoder_model.predict(packet_scaled_ae)
        recon_error = np.mean(np.square(packet_scaled_ae - reconstructions), axis=1)
        
        # Calculate confidence score (1 - normalized reconstruction error)
        confidence = 1.0 - min(1.0, recon_error[0] / (self.ae_threshold * 10))
        
        # Step 3: Autoencoder anomaly detection
        ae_flags = recon_error > self.ae_threshold
        
        # Step 4: Filter AE anomalies
        if not np.any(ae_flags):
            print("No anomalies detected by AE.")
            return [], confidence
            
        anomalies = packet_scaled_ae[ae_flags]
        anomalies_raw = packet[ae_flags]
        
        # Step 5: SVM refinement
        anomalies_raw_scaled = self.svm_scaler.transform(anomalies_raw)
        svm_flags = self.svm_model.predict(anomalies_raw_scaled)
        svm_mask = (svm_flags == -1)
        
        if not np.any(svm_mask):
            print("No confirmed attacks after SVM.")
            return [], confidence
            
        refined_anomalies = anomalies[svm_mask]
        
        # Step 6: XGBoost classification
        xgb_preds = self.xgb_model.predict(refined_anomalies)
        labels = self.xgb_label_encoder.inverse_transform(xgb_preds)
        
        return labels, confidence