# RTSA Backend — Real-time Threshold Secret Architecture

RTSA is a high-security, open-access FastAPI backend designed to split, securely embed, asynchronously distribute, and reconstruct sensitive secrets (e.g., master API keys, cloud credentials, private keys). 

Instead of relying on single-point database storage or vulnerable plain-text delivery, RTSA combines **Shamir's Secret Sharing (SSS)**, **Least Significant Bit (LSB) Steganography**, **Multi-Recipient RSA Encryption**, and **Asynchronous Email Dispatch**.

---

## Key Features

* **Shamir's Secret Sharing (SSS):** Splits secrets into $n$ unique mathematical shares across finite Galois Field $\text{GF}(2^8)$ arithmetic. Any threshold $k$ ($k \le n$) shares can reconstruct the exact original secret.
* **LSB Steganography:** Embeds encrypted secret shares silently inside ordinary PNG cover images without perceptual degradation ($\text{PSNR} > 40\text{ dB}$, $\text{SSIM} \approx 1.0$).
* **Image Quality Verification:** Automatically calculates Peak Signal-to-Noise Ratio (PSNR) and Structural Similarity Index (SSIM) for every generated stego-image.
* **Multi-Recipient RSA Envelope Encryption:** Supports per-share RSA public key wrapping to restrict share decryption exclusively to authorized recipient key pairs.
* **Non-Blocking Async Email Delivery:** Dispatches emails carrying unique stego PNG image file attachments using FastAPI `BackgroundTasks`.
* **Zero-Lock Public Access:** Features automatic session fallback (`anon_<uuid>`), allowing the system to run seamlessly as an open tool without requiring user login.

---

## Project Architecture & Directory Structure

```text
rtasa_backend/
├── app/
│   ├── api/
│   │   ├── deps.py                        # Dependency Injection & Anonymous Owner Resolution
│   │   └── v1/
│   │       ├── api.py                     # Central API Router
│   │       └── endpoints/
│   │           ├── secrets.py             # Store & Reconstruct Endpoints
│   │           └── users.py               # User Management Endpoints
│   ├── core/
│   │   ├── config.py                      # Application Configuration
│   │   ├── crypto.py                      # SSS Galois Field GF(2^8) Implementation
│   │   ├── rsa.py                         # RSA Key Pair & Share Unwrapping Engine
│   │   ├── stego.py                       # LSB Pixel Steganography Engine
│   │   └── stego_metrics.py               # PSNR & SSIM Quality Calculation Engine
│   ├── db/
│   │   ├── base.py                        # SQLAlchemy Base Model
│   │   └── session.py                     # Database Session Provider
│   ├── models/
│   │   └── secret.py                      # SQLAlchemy Schemas (Secret, Share, User)
│   ├── schemas/
│   │   └── secret.py                      # Pydantic Request/Response Models
│   ├── services/
│   │   ├── email_service.py               # Async Email Dispatcher with PNG Attachments
│   │   └── secret_service.py              # Workflow Orchestrator (SSS + Stego + RSA + DB)
│   └── main.py                            # FastAPI Application Entrypoint
├── tests/                                 # Pytest Test Suite (18/18 Passing)
├── pytest.ini                             # Pytest Test Runner Config
├── requirements.txt                       # Frozen Dependencies
└── README.md                              # System Documentation

