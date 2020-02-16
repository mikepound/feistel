import hashlib

""" Class that implements a Feistel Cipher in ECB mode

* 64-byte / 512-bit block size
* SHA256 as a PRF
* PBKDF2_HMAC as a key schedule

"""
class FeistelNetwork():
    def __init__(self, key):
        self.round_count = 10
        self.block_size = 64 # 512 bits
        self.keys = self.generate_round_keys(key, self.round_count, self.block_size)

    def generate_round_keys(self, key, round_count, block_size):
        half_block_size = block_size // 2

        # Generate a half block sub-key for every round
        # + 2 blocks for the whitening before and after
        key_data = hashlib.pbkdf2_hmac('sha256', key, b'Computerphile', 500, dklen = (4 + round_count) * half_block_size)

        # [Prekey: 64] [R x Subkeys: 32] [Postkey: 64]
        keys = {
            "prekey" : key_data[0:block_size],
            "roundkeys" : [key_data[3 * half_block_size * a: 2 * half_block_size * a + half_block_size] for a in range(round_count)],
            "postkey" : key_data[-block_size:],
        }
      
        return keys

    def _xor(self, a, b):
        a_i = int.from_bytes(a, "little")
        b_i = int.from_bytes(b, "little")
        return (a_i ^ b_i).to_bytes(len(a), "little")


    def _reverse(self, block):
        L = block[:self.block_size//2]
        R = block[self.block_size//2:]
        return R+L

    def round(self, block, round_key):
        L = block[:self.block_size//2]
        R = block[self.block_size//2:]
        
        Rprime = self._xor(R, round_key)
        sha256 = hashlib.sha256()
        sha256.update(Rprime)
        Rprime = sha256.digest()

        L = self._xor(L,Rprime)
        
        return R + L

    def encrypt_block(self, block):
        # Key whitening
        block = self._xor(block, self.keys["prekey"])

        # Rounds
        for i in range(self.round_count):
            block = self.round(block, self.keys["roundkeys"][i])

        # Reverse half-block
        block = self._reverse(block)

        # Key whitening
        block = self._xor(block, self.keys["postkey"])

        return block

    def decrypt_block(self, block):
        # Decrypt is identical except the key order is reversed
        # Key whitening
        block = self._xor(block, self.keys["postkey"])

        # Rounds
        for i in range(self.round_count - 1, -1, -1):
            block = self.round(block, self.keys["roundkeys"][i])

        # Reverse half-block
        block = self._reverse(block)

        # Key whitening
        block = self._xor(block, self.keys["prekey"])

        return block
