# Michael Long
# CS485
# Project #1: Implementing "PSU-CRYPT"
# Main

import psu_crypt

def main():
    
    test_key = 0xabcdef0123456789
    test_plain = 0x0123456789abcdef

    ret = psu_crypt._encrypt_block(test_plain, test_key)
    print(f'Cipher Text: {int.to_bytes(ret, 8, "big").hex()}')
    ret2 = psu_crypt._decrypt_block(ret, test_key)
    print(f'Plaintext Text: {int.to_bytes(ret2, 8, "big").hex()}')

    pass

if __name__ == '__main__':
    main()