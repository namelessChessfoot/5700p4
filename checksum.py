def checksum(data: bytes) -> bytes:
    '''
        Calculate the 16-bit checksum of the given bytes
        Parameters:
            data: bytes
        Returns:
            The checksum
    '''
    copy = data
    if len(copy) % 2:
        copy += b"\0"
    ret = 0
    for i in range(0, len(copy), 2):
        a = copy[i] << 8
        a += copy[i+1]
        ret += a
        while ret > 0xffff:
            ret = (ret & 0xffff)+1
    ret = (~ret) & 0xffff
    return ret.to_bytes(2, "big")


def verify(data: bytes) -> bool:
    '''
        Verify if the given data is correctly checksumed.
        Parameters:
            data: bytes
        Returns:
            A boolean indicating the correctness
    '''
    res = checksum(data)
    return int.from_bytes(res, "big") == 0
