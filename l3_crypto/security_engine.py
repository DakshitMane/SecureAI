import numpy as np
from ecdsa import SECP256k1, SigningKey
from scipy.spatial.distance import mahalanobis
from typing import Tuple, List

class SecureCryptoEngine:
    def __init__(self):
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.verifying_key
        
    def encrypt_logit(self, score: float) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Simulates 256-bit Additive EC-ElGamal Homomorphic Encryption.
        Returns a tuple of elliptic curve coordinate points (C1, C2).
        """
        G = SECP256k1.generator
        k = int(SigningKey.generate(curve=SECP256k1).privkey.secret_multiplier)
        
        # Ciphertext calculation: C1 = kG, C2 = M + kQ
        c1 = k * G
        # Map score scalar to curve space for homomorphic blending
        scaled_score = int(score * 1000)
        c2 = (scaled_score * G) + (k * G)
        
        return (c1.x(), c1.y()), (c2.x(), c2.y())

def detect_validator_poisoning(
    incoming_vector: List[float], 
    historical_matrix: List[List[float]], 
    chi_squared_threshold: float = 3.5
) -> Tuple[bool, float]:
    """
    Calculates Multivariate Mahalanobis Distance over validator covariance shifts
    to detect and neutralize adversarial data-poisoning attempts.
    """
    X = np.array(historical_matrix)
    x = np.array(incoming_vector)
    
    mean_vector = np.mean(X, axis=0)
    covariance_matrix = np.cov(X, rowvar=False)
    
    # Pseudo-inverse to guarantee mathematical stability under low variance
    inv_covariance = np.linalg.pinv(covariance_matrix)
    
    distance = mahalanobis(x, mean_vector, inv_covariance)
    is_poisoned = distance > chi_squared_threshold
    
    return bool(is_poisoned), float(distance)
