# This file makes the routes directory a Python package
# You can add any shared route utilities here if needed
from .cuckoo_client import CuckooClient, analyze_file_with_cuckoo, CuckooAnalysisError