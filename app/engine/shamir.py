import os
import random
from app.core.exceptions import ShamirEngineError
from app.core.logging import logger

# 256-bit Mersenne Prime for Galois Field GF(P)
PRIME = 2**256 - 189

class ShamirEngine:
    """Enterprise $k$-of-$n$ Shamir's Secret Sharing Engine over GF(P)."""

    @classmethod
    def _eval_poly(cls, poly: list[int], x: int) -> int:
        result = 0
        for coeff in reversed(poly):
            result = (result * x + coeff) % PRIME
        return result

    @classmethod
    def split_secret(cls, secret_bytes: bytes, threshold_k: int, total_shares_n: int) -> list[tuple[int, bytes]]:
        """Splits secret_bytes into n shares requiring at least k to reconstruct."""
        if threshold_k > total_shares_n:
            raise ShamirEngineError("Threshold 'k' cannot be greater than total shares 'n'.")
        if threshold_k < 2:
            raise ShamirEngineError("Threshold 'k' must be at least 2.")

        try:
            secret_int = int.from_bytes(secret_bytes, byteorder="big")
            if secret_int >= PRIME:
                raise ShamirEngineError("Secret size exceeds maximum Galois field prime capacity.")

            # Generate random polynomial coefficients
            poly = [secret_int] + [
                int.from_bytes(os.urandom(32), byteorder="big") % PRIME
                for _ in range(threshold_k - 1)
            ]

            shares = []
            for i in range(1, total_shares_n + 1):
                y = cls._eval_poly(poly, i)
                shares.append((i, y.to_bytes(32, byteorder="big")))

            logger.info(f"Split secret into {total_shares_n} shares (Threshold k={threshold_k}).")
            return shares
        except Exception as e:
            if isinstance(e, ShamirEngineError):
                raise e
            raise ShamirEngineError(f"Failed to split secret: {str(e)}")

    @classmethod
    def combine_shares(cls, shares: list[tuple[int, bytes]]) -> bytes:
        """Reconstructs the original secret from k or more valid shares using Lagrange interpolation."""
        if not shares:
            raise ShamirEngineError("No shares provided for reconstruction.")

        try:
            x_s, y_s = [], []
            for x, y_bytes in shares:
                x_s.append(x)
                y_s.append(int.from_bytes(y_bytes, byteorder="big"))

            secret_int = 0
            for i in range(len(shares)):
                num, den = 1, 1
                for j in range(len(shares)):
                    if i != j:
                        num = (num * (-x_s[j])) % PRIME
                        den = (den * (x_s[i] - x_s[j])) % PRIME

                # Modular inverse using Fermat's Little Theorem
                lagrange_coeff = (num * pow(den, PRIME - 2, PRIME)) % PRIME
                secret_int = (secret_int + y_s[i] * lagrange_coeff) % PRIME

            reconstructed_bytes = secret_int.to_bytes(32, byteorder="big")
            logger.info("Successfully reconstructed secret from shares.")
            return reconstructed_bytes
        except Exception as e:
            logger.error(f"Shamir reconstruction failed: {str(e)}")
            raise ShamirEngineError("Failed to reconstruct secret. Shares may be invalid or corrupted.")