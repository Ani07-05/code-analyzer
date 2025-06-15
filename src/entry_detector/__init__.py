"""
Entry Point Detector Package - Phase 1
"""

# Import models first (they should always work)
from .models import (
    EntryPoint, EntryPointCandidate, EntryPointReport,
    EntryPointType, RiskLevel, InputSource, InputSourceType,
    RouteInfo, SecurityFeature
)

# Import risk assessor
try:
    from .risk_assessor import RiskAssessor
    print("✅ RiskAssessor imported successfully")
except ImportError as e:
    print(f"❌ RiskAssessor import failed: {e}")
    RiskAssessor = None

# Import main detector
try:
    from .detector import EntryPointDetector
    print("✅ EntryPointDetector imported successfully")
except ImportError as e:
    print(f"❌ EntryPointDetector import failed: {e}")
    EntryPointDetector = None

# Import Flask detector
try:
    from .framework_detectors.flask_detector import FlaskDetector
    print("✅ FlaskDetector imported successfully")
except ImportError as e:
    print(f"❌ FlaskDetector import failed: {e}")
    FlaskDetector = None

__version__ = '1.0.0'
__all__ = [
    'EntryPointDetector',
    'RiskAssessor', 
    'EntryPoint',
    'EntryPointCandidate',
    'EntryPointReport',
    'EntryPointType',
    'RiskLevel',
    'InputSource',
    'InputSourceType',
    'RouteInfo',
    'SecurityFeature',
    'FlaskDetector',
]