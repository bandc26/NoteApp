import os
from pathlib import Path

from PIL import Image, ImageDraw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


INPUT_FILE = "input.png"


# ---------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data.")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding.")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding.")

    return data[:-pad_len]


# ---------------------------------------------------------
# AES-ECB
# ---------------------------------------------------------

def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    padded = pkcs7_pad(data)

    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB()
    )

    encryptor = cipher.encryptor()

    return encryptor.update(padded) + encryptor.finalize()


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB()
    )

    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()

    return pkcs7_unpad(padded)


# ---------------------------------------------------------
# AES-GCM
# ---------------------------------------------------------

def aes_gcm_encrypt(
    data: bytes,
    key: bytes
) -> tuple[bytes, bytes]:

    nonce = os.urandom(12)

    aesgcm = AESGCM(key)

    ciphertext_with_tag = aesgcm.encrypt(
        nonce,
        data,
        None
    )

    return nonce, ciphertext_with_tag


def aes_gcm_decrypt(
    nonce: bytes,
    ciphertext_with_tag: bytes,
    key: bytes
) -> bytes:

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce,
        ciphertext_with_tag,
        None
    )


# ---------------------------------------------------------
# Image helpers
# ---------------------------------------------------------

def make_demo_image(path: str) -> None:
    """
    Create a simple black-and-white demo image if input.png is missing.

    This image has large flat regions, so ECB will visibly leak
    the shape of the drawing.
    """

    size = 256
    img = Image.new("L", (size, size), 255)
    draw = ImageDraw.Draw(img)

    # Body (filled ellipse)
    draw.ellipse((48, 48, 208, 208), fill=0)

    # Eyes (white circles)
    draw.ellipse((96, 96, 128, 128), fill=255)
    draw.ellipse((160, 96, 192, 128), fill=255)

    # Pupils (black dots)
    draw.ellipse((108, 108, 116, 116), fill=0)
    draw.ellipse((172, 108, 180, 116), fill=0)

    # Beak (triangle)
    draw.polygon(
        [(128, 144), (144, 144), (136, 160)],
        fill=255
    )

    img.save(path)
    print(f"Created demo image: {path}")


def prepare_image(image: Image.Image) -> Image.Image:
    """
    Convert to grayscale, binarize, and crop to a multiple of 16
    in both width and height.

    Grayscale: 1 pixel = 1 byte
    16 pixels = 16 bytes = 1 AES block
    """

    image = image.convert("L")

    # Binarize so that flat regions become exactly equal bytes.
    # This makes ECB block repetition clearly visible.
    image = image.point(lambda x: 0 if x < 128 else 255)

    width, height = image.size

    new_width = width - (width % 16)
    new_height = height - (height % 16)

    if new_width < 16 or new_height < 16:
        raise ValueError("Image is too small.")

    return image.crop((0, 0, new_width, new_height))


def save_image(
    filename: str,
    width: int,
    height: int,
    data: bytes
) -> None:

    image = Image.frombytes(
        "L",
        (width, height),
        data
    )

    image.save(filename)


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main() -> None:

    input_path = Path(INPUT_FILE)

    if not input_path.exists():
        print(f"{INPUT_FILE} not found. Creating a demo image...")
        make_demo_image(INPUT_FILE)

    # ---------------------------------------------------------
    # Load image
    # ---------------------------------------------------------

    original = Image.open(input_path)

    image = prepare_image(original)

    width, height = image.size

    raw_data = image.tobytes()

    print(f"Input image: {INPUT_FILE}")
    print(f"Prepared image size: {width} x {height}")
    print(f"Raw data size: {len(raw_data)} bytes")

    # Save the prepared plaintext for comparison
    save_image("prepared_plain.png", width, height, raw_data)
    print("Prepared plaintext saved: prepared_plain.png")

    # ---------------------------------------------------------
    # AES-256 key (classroom demo only)
    # ---------------------------------------------------------

    key = b"0123456789abcdef0123456789abcdef"

    # =========================================================
    # ECB
    # =========================================================

    ecb_ciphertext = aes_ecb_encrypt(raw_data, key)

    print(f"ECB ciphertext size: {len(ecb_ciphertext)} bytes")

    # Remove the final PKCS#7 padding block for visualization
    ecb_preview = ecb_ciphertext[:len(raw_data)]

    save_image("encrypted_ecb.png", width, height, ecb_preview)
    print("ECB preview saved: encrypted_ecb.png")

    # =========================================================
    # GCM
    # =========================================================

    gcm_nonce, gcm_ciphertext = aes_gcm_encrypt(raw_data, key)

    print(f"GCM ciphertext + tag size: {len(gcm_ciphertext)} bytes")
    print(f"GCM nonce: {gcm_nonce.hex()}")

    # GCM output = ciphertext + 16-byte authentication tag
    # Remove the tag only for visualization.
    gcm_preview = gcm_ciphertext[:len(raw_data)]

    save_image("encrypted_gcm.png", width, height, gcm_preview)
    print("GCM preview saved: encrypted_gcm.png")

    # =========================================================
    # Real decryption tests
    # =========================================================

    print("\n==== Decryption tests ====")

    ecb_decrypted = aes_ecb_decrypt(ecb_ciphertext, key)
    gcm_decrypted = aes_gcm_decrypt(gcm_nonce, gcm_ciphertext, key)

    ecb_ok = ecb_decrypted == raw_data
    gcm_ok = gcm_decrypted == raw_data

    print(f"ECB decryption success: {ecb_ok}")
    print(f"GCM decryption success: {gcm_ok}")

    # =========================================================
    # Save recovered images
    # =========================================================

    if ecb_ok:
        save_image("decrypted_ecb.png", width, height, ecb_decrypted)
        print("Recovered ECB image: decrypted_ecb.png")

    if gcm_ok:
        save_image("decrypted_gcm.png", width, height, gcm_decrypted)
        print("Recovered GCM image: decrypted_gcm.png")

    # =========================================================
    # Observation
    # =========================================================

    print("\n==== Lab observation ====")
    print("1. ECB preserves repeated plaintext-block patterns.")
    print("2. GCM hides plaintext patterns and appears random.")
    print("3. ECB should never be used for secure encryption.")
    print("4. GCM provides confidentiality and integrity.")


if __name__ == "__main__":
    main()