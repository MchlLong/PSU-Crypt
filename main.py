# Michael Long
# CS485
# Project #1: Implementing "PSU-CRYPT"
# Main

import psu_crypt

def main():
    test_key = 0xabcdef0123456789
    key_len = 64
    print(f'Key Before Stream: {int.to_bytes(test_key, 8, "big").hex()}')
    ret = psu_crypt._keystream(test_key, key_len, 0)
    pass

if __name__ == '__main__':
    main()