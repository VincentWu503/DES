import argparse
import os
import services.key as Key
import services.mode as Mode
from services.image import get_pixels, put_pixels

# to do list : buat pilihan agar user bisa encrypt dan decrypt

def main():
    parser = argparse.ArgumentParser(
        description="Program Python untuk enkripsi dan dekripsi gambar mode Counter (CTR).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("input", type=str, help="Path absolut gambar yang akan dienkripsi atau didekripsi.")
    parser.add_argument("action", type=str, choices= ["encrypt", "decrypt"], help="Pilihan untuk melakukan enkripsi atau dekripsi gambar.")
    parser.add_argument("mode", type=str, choices= ["ECB", "CTR"], help= "Mode yang digunakan untuk DES (ECB atau CTR).")
    parser.add_argument("key", type=int, help="Kunci yang digunakan untuk DES. Jika ukuran kunci kurang dari 64-bit, " 
    "argumen kunci akan melewati proses padding melalui fungsi generate_key")

    args = parser.parse_args()

    try:
        pixels = get_pixels(args.input)
    except ValueError:
        raise

    key = Key.generate_key(args.key)
    subkeys = Key.generate_subkeys(key)

    match args.mode:
        case "ECB":
            if args.action == "encrypt":
                pixels_padded = Mode.pad_text(pixels)
                encrypted_data = Mode.ecb_encryption(pixels_padded, subkeys)
                encrypted_data = Mode.unpad_text(encrypted_data, len(pixels_padded) - len(pixels))
            elif args.action == "decrypt":
                pixels_padded = Mode.pad_text(pixels)
                decrypted_data = Mode.ecb_decryption(pixels_padded, subkeys)
                decrypted_data = Mode.unpad_text(decrypted_data, len(pixels_padded) - len(pixels))
        case "CTR":
            if args.action == "encrypt":
                encrypted_data = Mode.ctr(pixels, subkeys)
            elif args.action == "decrypt":
                decrypted_data = Mode.ctr(pixels, subkeys)

    directory, file = os.path.split(args.input)
    filename, extension = file.split(".")

    if args.action == "encrypt":
        suffix = "_ENCRYPTED"
    else:
        suffix = "_DECRYPTED"

    output_file = f"{directory}/{filename}{suffix}_{args.mode}.{extension}"
        
    if args.action == "encrypt":
        put_pixels(args.input, output_file, encrypted_data)
    else:
        put_pixels(args.input, output_file, decrypted_data)

    print(f"Gambar berhasil tersimpan di {output_file}.")

if __name__ == "__main__":
    main()