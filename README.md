# Feistel Cipher Example

This is a feistel cipher implementation I wrote for a Computerphile video. While I started with this being a simple couple of functions, I realised that if I wanted proper file IO, I needed to code up a mode of operation. It now encrypts files and outputs ciphertext as files, theoretically you could write your own functions to call the cipher itself, which is found in `feistel.py`. Feel free to edit, change, reuse the code for whatever you wish.

If you'd like to learn more about Feistel ciphers, please watch [my video](https://www.youtube.com/watch?v=FGhj3CGxl8I). There is also a detailed article on wikipedia [here](https://en.wikipedia.org/wiki/Feistel_cipher)

Some examples of famous feistel ciphers are [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) and [Twofish](https://en.wikipedia.org/wiki/Twofish)

## Usage
##### Encryption
`python encrypt.py -e -m ECB input_file output_file`
##### Decryption
`encrypt.py -d -m ECB input_file output_file`

At the moment only ECB and CBC modes of operation are permitted.

## Cool things that could be added
This cipher is a bit bland, it would benefit from:
* More modes of operation. We can't add AEAD, but CBC (now added) and CTR mode would be a start.
* Better handling of keys. Reading input is slow and mistake-prone, and keys are never long enough. Keys could be optionally read from an additional file.
* I'm sure the key schedule could be improved, but i'm tempted to leave it as that was what was used in the video.

## Reasons not to use this cipher for real!
This cipher is just a demonstration, and for fun. Please don't use it on anything you actually need to secure. Here are some issues off the top of my head:

* It's slow, may not be a problem based on your use case, but noone is attempting to write fast ciphers in python anyway!
* It doesn't conveniently use 256-bit keys. Because it reads strings as an input, these are likely to be much too short to be secure. This will also encrypt using no key - bad!
* I've paid absolutely no attention to safe memory use, cache timings etc. So it's conceivable that the cipher is vulnerable while it's running - possibly after too since it doesn't wipe the key from memory.
* It defaults to ECB mode - and indeed currently no other modes are implemented
* It provides no message integrity since it doesn't use HMAC, GCM etc.
