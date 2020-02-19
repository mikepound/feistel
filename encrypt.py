import hashlib
import os
import argparse
from pkcs import PKCS7
from feistel import FeistelNetwork
from modes import ECB, CBC
from iterators import file_block_iterator, eof_signal_iterator

"""
The Mike Encryption Standard

Never use this in production code!
"""
def main():
    # Command line arguments
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action="store_true")
    group.add_argument('-d', '--decrypt', action="store_true")
    parser.add_argument('-m', '--mode', type=str, default='ECB')
    parser.add_argument('-i', '--iv', type=str)
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    args = parser.parse_args()

    key = input("Enter {} key: ".format("encryption" if args.encrypt else "decryption"))
    key = key.encode("UTF-8")

    cipher = FeistelNetwork(key)
    
    # Select mode of operation
    if args.mode == "ECB":
        padding_scheme = PKCS7(cipher.block_size)
        mode = ECB(cipher, padding_scheme)
    elif args.mode == "CBC":
        #if no IV was informed on command line, generate one (pseudo)randomly
        iv = args.iv.encode('utf-8') if args.iv else\
            os.urandom(cipher.block_size)
        #test for a valid IV length
        if len(iv) != cipher.block_size:
            raise ValueError("Invalid IV length")
        padding_scheme = PKCS7(cipher.block_size)
        mode = CBC(cipher, iv, padding_scheme)
    else:
        raise ValueError("Mode of operation {} is not recognised".format(args.mode))

    # Encrypt or decrypt
    if args.encrypt:
        file_blocks = file_block_iterator(args.input_file, cipher.block_size)
        with open(args.output_file, 'wb') as f:
            for ciphertext in mode.encrypt(file_blocks):
                f.write(ciphertext)
    else:
        file_blocks = file_block_iterator(args.input_file, cipher.block_size)
        with open(args.output_file, 'wb') as f:
            for plaintext in mode.decrypt(file_blocks):
                f.write(plaintext)


if __name__ == "__main__":
    main()
