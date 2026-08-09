import cv2
import numpy as np
from skimage.metrics import structural_similarity as ssim


def compute_image_metrics(cover_bytes: bytes, stego_bytes: bytes) -> dict:
    """
    Decodes cover and stego PNG image bytes and computes PSNR and SSIM metrics.
    """
    # 1. Decode bytes into OpenCV uint8 image matrices (BGR)
    cover_np = cv2.imdecode(np.frombuffer(cover_bytes, np.uint8), cv2.IMREAD_COLOR)
    stego_np = cv2.imdecode(np.frombuffer(stego_bytes, np.uint8), cv2.IMREAD_COLOR)

    if cover_np is None or stego_np is None:
        raise ValueError("Could not decode cover or stego image bytes.")

    if cover_np.shape != stego_np.shape:
        raise ValueError("Cover image and stego image dimensions do not match.")

    # 2. Compute PSNR (Peak Signal-to-Noise Ratio)
    psnr_value = cv2.PSNR(cover_np, stego_np)

    # 3. Compute SSIM (Structural Similarity Index) across multi-channel BGR image
    ssim_value, _ = ssim(
        cover_np, 
        stego_np, 
        channel_axis=2, 
        full=True
    )

    return {
        "psnr_db": round(float(psnr_value), 2),
        "ssim": round(float(ssim_value), 4),
    }