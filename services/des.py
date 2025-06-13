import data.constants as constants
import numpy as np
import numpy.typing as npt

# encrypt (text, subkeys: <return type>)
def encrypt(plaintext, subkeys: npt.NDArray[np.uint8]):
    # permutasi awal 
    # karena konstanta IP didefinisikan berdasarkan pengindeksan 1,
    # sedangkan array menggunakan pengindeksan 0, kurangi dengan 1
    permutation = plaintext[constants.IP - 1]
    
    # bagi menjadi dua bagian, kiri dan kanan, masing-masing 32 bit
    l = permutation[:32]
    r = permutation[32:]

    for subkey in subkeys:
        # bagian dari feistel function
        # ekspansi r dari 32 bit menjadi 48 bit
        xor = subkey ^ r[constants.E_BIT - 1]
        result = np.empty((0,), dtype=np.uint8)

        # iterasi 8 s-box
        for i in range(8):
            six_bits = xor[i * 6 : (i + 1) * 6]
            row = (six_bits[0] << 1) + six_bits[5]
            col = (six_bits[1] << 3) + (six_bits[2] << 2) + (six_bits[3] << 1) + six_bits[4]

            s_box_value = constants.S_BOXES[i][row][col]
            result = np.concatenate((result, constants.S_BOX_CONVERSION[s_box_value]))

        f = result[constants.P - 1]
        l, r = r, l ^ f

    return np.concatenate((r, l))[constants.IP_I - 1]

# untuk mode CTR, tidak pernah menggunakan fungsi ini
def decrypt(ciphertext, subkeys: npt.NDArray[np.uint8]):
    permutation = ciphertext[constants.IP - 1]
    l = permutation[:32]
    r = permutation[32:]

    # subkeys harus dibalik urutannya untuk dekripsi
    for subkey in reversed(subkeys):
        # kurangi index r dengan 1 karena 0 based array indexing
        # numpy array menggunakan 0 based indexing sedangkan E_BIT
        # menggunakan 1 based indexing
        xor = subkey ^ r[constants.E_BIT - 1]
        result = np.empty((0,), dtype=np.uint8)

        for i in range(8):
            six_bits = xor[i * 6 : (i + 1) * 6]
            row = (six_bits[0] << 1) + six_bits[5]
            col = (six_bits[1] << 3) + (six_bits[2] << 2) + (six_bits[3] << 1) + six_bits[4]

            s_box_value = constants.S_BOXES[i][row][col]
            result = np.concatenate((result, constants.S_BOX_CONVERSION[s_box_value]))

        f = result[constants.P - 1]
        l, r = r, l ^ f

    return np.concatenate((r, l))[constants.IP_I - 1]

