def eof_signal_iterator(it):
    # Iterates through an iterator while signalling EOF (the end of the iterator in this case)
    it = iter(it)
    prev = next(it)
    for item in it:
        yield prev, False
        prev = item
    # Last item
    yield prev, True

def file_block_iterator(path, block_size):
    with open(path, 'rb') as f:
        data = f.read(block_size)
        while data != b"":
            yield data
            data = f.read(64)

def list_block_iterator(message, block_size):
    for idx in range (0, len(message), block_size):
        yield message[idx:idx+block_size]