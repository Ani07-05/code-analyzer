"""Framework Detectors Package"""
try:
    from .base_detector import BaseFrameworkDetector
    from .flask_detector import FlaskDetector
except ImportError:
    pass  # Files will be created
