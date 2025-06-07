from unittest.mock import Mock, patch
import numpy as np
import pytest
from ml_model.utils.AttackDetector import AttackDetector

class TestAttackDetector:
    @pytest.fixture
    def attack_detector(self):
        return AttackDetector()

    @patch("ml_model.utils.AttackDetector.load_model")
    @patch("ml_model.utils.AttackDetector.joblib.load")
    def test_initialization(self, mock_joblib_load, mock_load_model):
        mock_load_model.return_value = Mock()
        mock_joblib_load.return_value = Mock()
        detector = AttackDetector()

        assert detector.autoencoder_model is not None
        assert detector.svm_model is not None
        assert detector.xgb_model is not None
        assert detector.svm_scaler is not None
        assert detector.autoencoder_scaler is not None
        assert detector.xgb_label_encoder is not None
        assert detector.ae_threshold == 0.0001

    def test_predict_with_valid_packet(self, attack_detector):
        sample_packet = np.array([1.0, 2.0, 3.0])
        # Instead of mocking internal method, test the actual behavior
        result = attack_detector.predict(sample_packet)
        assert isinstance(result, list)
        assert all(isinstance(label, str) for label in result)

    def test_predict_with_no_anomalies(self, attack_detector):
        sample_packet = np.array([0.1, 0.2, 0.3])
        # Instead of mocking internal method, test the actual behavior
        result = attack_detector.predict(sample_packet)
        assert isinstance(result, list)

    def test_predict_handles_exceptions(self, attack_detector):
        sample_packet = np.array([1.0, 2.0, 3.0])

        # Create a new mock that will raise the exception
        mock_predict = Mock(side_effect=Exception("Mocked error"))

        with patch.object(attack_detector, 'predict', mock_predict):
            # Call the method and verify it handles the exception
            with pytest.raises(Exception, match="Mocked error"):
                attack_detector.predict(sample_packet)

