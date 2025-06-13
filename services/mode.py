import numpy as np
import numpy.typing as npt
from services.des import encrypt
from services.des import decrypt
from tqdm import tqdm

BLOCK_SIZE_BITS = 64
SEGMENT_SIZE_BITS = 8

def pad_text(text: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    padding = np.zeros(BLOCK_SIZE_BITS - (len(text) % BLOCK_SIZE_BITS), dtype=np.uint8)
    return np.concatenate((text, padding), dtype=np.uint8)

def unpad_text(text: npt.NDArray[np.uint8], padding_length: int) -> npt.NDArray[np.uint8]:
    return text[:len(text) - padding_length]

def ecb_encryption(text: npt.NDArray[np.uint8], subkeys: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    num_blocks = len(text) // BLOCK_SIZE_BITS
    encryption = np.empty(num_blocks * BLOCK_SIZE_BITS, dtype=np.uint8)

    for i in tqdm(
        range(num_blocks),
        desc="Enkripsi dengan mode ECB",
        total=num_blocks
    ):
        start = i * BLOCK_SIZE_BITS
        end = start + BLOCK_SIZE_BITS
        encrypted_block = encrypt(text[start:end], subkeys)
        encryption[start:end] = encrypted_block

    return encryption

def ecb_decryption(ciphertext: npt.NDArray[np.uint8], subkeys: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    num_blocks = len(ciphertext) // BLOCK_SIZE_BITS
    decryption = np.empty(num_blocks * BLOCK_SIZE_BITS, dtype=np.uint8)

    for i in tqdm(
        range(num_blocks),
        desc="Dekripsi dengan mode ECB",
        total=num_blocks
    ):
        start = i * BLOCK_SIZE_BITS
        end = start + BLOCK_SIZE_BITS
        encrypted_block = decrypt(ciphertext[start:end], subkeys)
        decryption[start:end] = encrypted_block

    return decryption

def ctr(text: npt.NDArray[np.uint8], subkeys: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    num_blocks = len(text) // BLOCK_SIZE_BITS
    ciphertext = np.empty(num_blocks * BLOCK_SIZE_BITS, dtype=np.uint8)
    counter = 0
    bit_size = 64
    # remaining_bits = len(text) % BLOCK_SIZE_BITS

    # fungsi bawaan py untuk tampilan loading
    for i in tqdm(
        range(num_blocks),
        desc="Memroses dengan mode CTR",
        total=num_blocks
    ):
        # counter_block = np.array([(counter >> bit) & 1 for bit in range(bit_size - 1, -1, -1)], dtype=np.uint8)
        counter_block = np.unpackbits(np.array([counter], dtype=np.uint64).view(np.uint8))
        encryption = encrypt(counter_block, subkeys)
        start = i * BLOCK_SIZE_BITS
        end = start + BLOCK_SIZE_BITS
        plaintext_block = text[start:end]
        ciphertext_block = np.bitwise_xor(plaintext_block, encryption)
        ciphertext[start:end] = ciphertext_block

        # batas counter = 64-bit integer limit
        counter = (counter + 1) % (2 ** bit_size)

    counter = 0

    return ciphertext