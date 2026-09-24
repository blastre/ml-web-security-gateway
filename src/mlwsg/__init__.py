"""ML-Assisted Web Security Gateway with Agentic Remediation.

Phase 1 package: controlled SSRF testbed, synthetic dataset generation,
URL/request feature engineering, and the three trained detection models
(Logistic Regression, Random Forest, Isolation Forest).

Phase 2 (hybrid gateway + egress guard) and Phase 3 (agentic remediation)
build on the public interfaces exported here.
"""

__version__ = "1.0.0"
__phase__ = 1

__all__ = ["__version__", "__phase__"]
