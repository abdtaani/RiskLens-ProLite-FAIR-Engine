# utils/helpers.py
# Contains utility functions for the RiskLens ProLite project.

import logging
import os
from datetime import datetime

def setup_logging(log_file: str = 'risklens_prolite.log', level: int = logging.INFO) -> logging.Logger:
    """
    Sets up a standardized logging configuration for the application.

    Args:
        log_file (str): The name of the log file. Defaults to 'risklens_prolite.log'.
        level (int): The logging level (e.g., logging.INFO, logging.DEBUG).
                     Defaults to logging.INFO.

    Returns:
        logging.Logger: The configured logger instance.
    """
    # Ensure the logs directory exists
    log_directory = 'logs'
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    log_path = os.path.join(log_directory, log_file)

    # Get the root logger
    logger = logging.getLogger('RiskLensProLite')
    logger.setLevel(level)

    # Prevent adding multiple handlers if the logger is already configured
    if not logger.handlers:
        # File handler
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(level)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Console handler (for INFO and above)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO) # Always show INFO and above on console
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger

def get_current_year() -> int:
    """
    Returns the current year. Useful for parsing syslog timestamps.
    """
    return datetime.now().year

def get_previous_year() -> int:
    """
    Returns the previous year. Useful for handling year rollover in syslog timestamps.
    """
    return datetime.now().year - 1

# Example usage (for testing this module directly)
if __name__ == "__main__":
    test_logger = setup_logging(level=logging.DEBUG)
    test_logger.debug("This is a debug message.")
    test_logger.info("This is an info message.")
    test_logger.warning("This is a warning message.")
    test_logger.error("This is an error message.")
    test_logger.critical("This is a critical message.")

    print(f"Current year: {get_current_year()}")
    print(f"Previous year: {get_previous_year()}")