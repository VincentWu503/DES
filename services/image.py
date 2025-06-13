import numpy as np
import numpy.typing as npt
from PIL import Image

# ubah matriks gambar ke matriks biner
def integer_array_to_binary_array(integer_array: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    return ((np.reshape(integer_array, (-1, 1)) & (1 << np.arange(8, dtype=np.uint8))) != 0).astype(np.uint8)[:, ::-1]

# ubah matriks biner ke matriks gambar
def binary_array_to_integer_array(binary_array: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    return (binary_array * (1 << np.arange(8)[::-1])).sum(axis=1)


def get_pixels(input_path: str) -> npt.NDArray[np.uint8]:
    with Image.open(input_path) as image:
        if image.mode not in frozenset(("RGB", "RGBA")):
            raise ValueError(f"Image mode {image.mode} not supported.")
        
        data = np.array(image.getdata(), dtype=np.uint8)

        return integer_array_to_binary_array(data).reshape(-1)


def put_pixels(input_path: str, output_path: str, encrypted_data: npt.NDArray[np.uint8]):
    with Image.open(input_path) as image:
        match image.mode:
            case "RGB":
                encrypted_data = encrypted_data.reshape(-1, 24)

                pixel_values = (
                    binary_array_to_integer_array(encrypted_data[:, :8]).astype(np.uint8),
                    binary_array_to_integer_array(encrypted_data[:, 8:16]).astype(np.uint8),
                    binary_array_to_integer_array(encrypted_data[:, 16:24]).astype(np.uint8),
                )
            case "RGBA":
                encrypted_data = encrypted_data.reshape(-1, 32)

                pixel_values = (
                    binary_array_to_integer_array(encrypted_data[:, :8]).astype(np.uint8),
                    binary_array_to_integer_array(encrypted_data[:, 8:16]).astype(np.uint8),
                    binary_array_to_integer_array(encrypted_data[:, 16:24]).astype(np.uint8),
                    binary_array_to_integer_array(encrypted_data[:, 24:]).astype(np.uint8)
                )

        encrypted_image = list(zip(*pixel_values))

        image.putdata(encrypted_image)
        image.save(output_path)