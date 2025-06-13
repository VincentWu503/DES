import data.constants as constants
import numpy as np
import numpy.typing as npt


def generate_key(integer: int) -> npt.NDArray[np.uint8]:
    binary_strings = list(format(integer, "b"))
    array = np.array(binary_strings, dtype=np.uint8)
    padding = 64 - len(binary_strings)
    
    return np.pad(array, (padding, 0))


def generate_subkeys(key: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    permuted_key = key[constants.PC_1 - 1]

    c = permuted_key[:28]
    d = permuted_key[28:]

    subkeys = np.empty((16, 48), dtype=np.uint8)

    for i, shift in enumerate(constants.SHIFTS):
        c = np.roll(c, shift * -1)
        d = np.roll(d, shift * -1)

        cd_combined = np.hstack((c, d))

        subkey = cd_combined[constants.PC_2 - 1]
        subkeys[i] = subkey

    return subkeys