# Examples

This directory contains example ciphertexts obtained by encrypting message.bin under different keys.

| File          | Key           | Mode  | Nonce                              |
| ------------- | ------------- | ----- | ---------------------------------- |
| ciphertext.1  | 12345         | ECB   |                                    |
| ciphertext.2  | Computerphile | ECB   |                                    |
| ciphertext.3  | a7f101gh6kE22 | ECB   |                                    |
| ciphertext.4  | 87654321      | CBC   |                                    |
| ciphertext.5  | Computerphile | CBC   |                                    |
| ciphertext.6  | secret_key    | CBC   |                                    |
| ciphertext.7  | c0ldc0ffee    | CTR   | `42`                               |
| ciphertext.8  | Computerphile | CTR   | `this_is_a_number_used_only_once.` |
| ciphertext.9  | Computerphile | CTR   | `1337`                             |
