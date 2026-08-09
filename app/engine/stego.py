import io
from PIL import Image
from app.core.exceptions import StegoEngineError
from app.core.logging import logger


class StegoEngine:
    """Enterprise LSB Steganography Engine for PNG images."""

    @classmethod
    def embed_data(cls, image_bytes: bytes, data_to_hide: bytes | tuple) -> bytes:
        """Embeds arbitrary byte payload into the least significant bits of an image."""
        # Safety check: If a tuple like (idx, bytes) was passed, extract just the bytes portion
        if isinstance(data_to_hide, tuple):
            data_to_hide = data_to_hide[1]

        try:
            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            width, height = img.size
            total_pixels = width * height

            data_len = len(data_to_hide)
            payload = data_len.to_bytes(4, byteorder="big") + data_to_hide

            bits_needed = len(payload) * 8
            if bits_needed > total_pixels * 3:
                raise StegoEngineError(
                    f"Image capacity exceeded. Needs {bits_needed} bits, capacity is {total_pixels * 3} bits."
                )

            bits = []
            for byte in payload:
                for i in range(8):
                    bits.append((byte >> (7 - i)) & 1)

            # Modern Pillow pixel loading via bytes buffer
            pixel_data = bytearray(img.tobytes())
            bit_idx = 0
            total_bits = len(bits)

            for i in range(len(pixel_data)):
                if bit_idx >= total_bits:
                    break
                pixel_data[i] = (pixel_data[i] & ~1) | bits[bit_idx]
                bit_idx += 1

            stego_img = Image.frombytes("RGB", img.size, bytes(pixel_data))

            out_buffer = io.BytesIO()
            stego_img.save(out_buffer, format="PNG")
            logger.info("Successfully embedded payload into stego image.")
            return out_buffer.getvalue()

        except Exception as e:
            if isinstance(e, StegoEngineError):
                raise e
            logger.error(f"Steganography embedding failed: {str(e)}")
            raise StegoEngineError(f"Embedding failed: {str(e)}")

    @classmethod
    def extract_data(cls, stego_image_bytes: bytes) -> bytes:
        """Extracts embedded byte payload from stego PNG image."""
        try:
            img = Image.open(io.BytesIO(stego_image_bytes)).convert("RGB")
            pixel_bytes = img.tobytes()

            extracted_bits = [b & 1 for b in pixel_bytes]

            def bits_to_bytes(bit_list: list[int]) -> bytes:
                byte_arr = bytearray()
                for i in range(0, len(bit_list), 8):
                    chunk = bit_list[i : i + 8]
                    if len(chunk) < 8:
                        break
                    val = 0
                    for b in chunk:
                        val = (val << 1) | b
                    byte_arr.append(val)
                return bytes(byte_arr)

            all_bytes = bits_to_bytes(extracted_bits)
            if len(all_bytes) < 4:
                raise StegoEngineError(
                    "No valid steganographic payload header found."
                )

            payload_len = int.from_bytes(all_bytes[:4], byteorder="big")
            if len(all_bytes) < 4 + payload_len:
                raise StegoEngineError(
                    "Corrupted steganographic payload detected."
                )

            extracted_payload = all_bytes[4 : 4 + payload_len]
            logger.info("Successfully extracted payload from stego image.")
            return extracted_payload

        except Exception as e:
            if isinstance(e, StegoEngineError):
                raise e
            logger.error(f"Steganography extraction failed: {str(e)}")
            raise StegoEngineError(f"Extraction failed: {str(e)}")