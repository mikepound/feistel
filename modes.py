from iterators import eof_signal_iterator

""" Classes implementing modes of encryption:

* We can extend this, currently only ECB and CBC is supported

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

#CBC mode implemented by Lucas V. Araujo <https://github.com/LvMalware/>

#CBC encrypts each block xor'd against the cipher text of the previous block.
#The first block is xor'd against a 0th block, the initialization vector (IV)

class CBC(ModeOfOperation):
    
    def __init__(self, cipher, iv, padding_scheme):
        super(CBC, self).__init__(cipher=cipher, iv=iv)
        #initialize cipher_block with value None
        self.cipher_block = None
        self.padding_scheme = padding_scheme

    def _xor(self, block1, block2):
        return bytes([a ^ b for a, b in zip(block1, block2)])

    def encrypt(self, block_iterator):
        eof_iterator = eof_signal_iterator(block_iterator)
        for data, eof in eof_iterator:
            
            if not self.cipher_block:
                #executed only once, on the first iteration
                self.cipher_block = self.iv
                #just return the IV, to be used as the first 64 bytes of the file
                yield self.cipher_block
            
            if not eof:
                self.cipher_block = self.cipher.encrypt_block(
                    self._xor(data, self.cipher_block)
                )
            else:
                #executed only once, for the last block of the file
                block = data if not eof else self.padding_scheme.apply(data)
                if len(block) == self.block_size:
                    self.cipher_block = self.cipher.encrypt_block(
                        self._xor(block, self.cipher_block)
                    )
                elif len(block) == 2 * self.block_size:
                    last_block = self.cipher.encrypt_block(
                        self._xor(block[:self.block_size], self.cipher_block)
                    )
                    #This will append an entire block of padding (??)
                    self.cipher_block = self.cipher.encrypt_block(
                        self._xor(block[self.block_size:], last_block)
                    )
                    #set the cipher_block variable to be last block of real data 
                    #prepended to the extra block of padding
                    self.cipher_block = last_block + self.cipher_block
                else:
                    raise Exception("Padding error: Padding scheme returned " +
                        "data that is not a multiple of the block length"
                    )
            yield self.cipher_block
    
    def decrypt(self, block_iterator):
        eof_iterator = eof_signal_iterator(block_iterator)

        #Always get the first 64 bytes of the data as IV. Even if it was already
        #supplied on the command line
        self.cipher_block, eof = next(eof_iterator)

        for data, eof in eof_iterator:
            plaintext = self._xor(
                self.cipher.decrypt_block(data), self.cipher_block
            )
            self.cipher_block = data
            block = plaintext if not eof else \
                self.padding_scheme.remove(plaintext)
            yield block