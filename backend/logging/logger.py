import logging
import os
from datetime import datetime

class IDSLogger:
    def __init__(self, log_dir="logs", log_filename=None):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        if log_filename is None:
            log_filename = f"ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        log_path = os.path.join(log_dir, log_filename)

        # Create logger
        self.logger = logging.getLogger("IDSLogger")
        self.logger.setLevel(logging.DEBUG)

        # Formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # File handler
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)

        # Stream handler (optional: print to console)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)

        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(stream_handler)

    def get_logger(self):
        return self.logger