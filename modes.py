from iterators import eof_signal_iterator

""" Classes implementing modes of encryption:

* We can extend this, currently only ECB is supported

"""
class ModeOfOperation():
    def __init__(self, cipher, iv = None, nonce = None):
        self.cipher = cipher
        self.iv = iv
        self.nonce = nonce
        self.block_size = cipher.block_size

class ECB(ModeOfOperation):
    def __init__(self, cipher, padding_scheme):
        super(ECB, self).__init__(cipher)
        self.padding_scheme = padding_scheme

    def encrypt(self, block_iterator):
        # Wrap file / list iterator inside eof_signal_iterator
        eof_iterator = eof_signal_iterator(block_iterator)

        for data, eof in eof_iterator:
            if not eof:
                ciphertext = self.cipher.encrypt_block(data)
            else:
                block = data if not eof else self.padding_scheme.apply(data)
                # Padding should return 1 or 2 blocks
                if len(block) == self.block_size:
                    ciphertext = self.cipher.encrypt_block(block)
                elif len(block) == self.block_size * 2:
                    ciphertext = self.cipher.encrypt_block(block[:self.block_size]) \
                               + self.cipher.encrypt_block(block[self.block_size:])

                else:
                    raise Exception("Padding e_rror: Padding scheme returned data that is not a multiple of the block length")
            yield ciphertext

    def decrypt(self, block_iterator):
        # Wrap file / list iterator inside eof_signal_iterator
        eof_iterator = eof_signal_iterator(block_iterator)
        
        for data, eof in eof_iterator:
            plaintext = self.cipher.decrypt_block(data)
            block = plaintext if not eof else self.padding_scheme.remove(plaintext)
            yield block
