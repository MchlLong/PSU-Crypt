# Michael Long
# CS485
# Project #1: Implementing "PSU-CRYPT"
# PSU-CRYPT

# Constants
LEFT = 0
RIGHT = 1

f_table = [0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46]
def _encrypt_block(data, key):
    # Encrypt
    print(int.to_bytes(data, 8, "big").hex())
    # Whiten the input
    # Divide key into four streams
    r = _split(data)
    k = _split(key)

    print(r)
    print(k)
    for i in range(4):
        print(int.to_bytes(r[i] ^ k[i], 8, "big").hex())
    print(int.to_bytes(data ^ key, 8, "big").hex())
    # Pass through 16 rounds of the F function

    # Undo last swap

    # Whiten the output

    pass

def _decrypt_block(data, key):
    # Decrypt
    pass

def _feistel():
    # Apply F-box 
    pass

def _keystream(key, key_length, direction):
    # Generate keystream from key
    # Returns list of keys

    # Verify that key is 64 bits, 80 bits, or 128 bits
    # Verify that the key's length divides evenly into 
    if (key_length % 8 != 0):
        return -1

    ret = []
    temp_key = key          # Standard shift key used to generate 0 ~ 191 K' values
    temp_key_truncate = 0   # Temporary shift key to do many right shifts to truncate and obtain the proper value
    counter_truncate = 0    # Counter to truncate 'X' bytes where 'X' is two times the counter
    counter_side_swap = 0   # Counter to swap between right half of key and left half of key

    # Loop through all 192 subkeys
    for i in range(192):

        temp_key = (_bit_rotate(temp_key, 64, LEFT))    # Rotate left bit
        temp_key_truncate = temp_key                    # Hold onto a copy to do truncation and several shifts right
        
        # First twelve keys are on right half of keyspace (0 ~ 11)
        if (counter_side_swap < 12):
            # Drop right most two hex values
            for j in range(counter_truncate):
                for k in range(8):
                    temp_key_truncate = (_bit_rotate(temp_key_truncate, 64, RIGHT))
        # Remaining twelve keys on the left half of the keyspace (12 ~ 23)
        else:
            # Shift over to drop right half of hex
            for l in range(32):
                temp_key_truncate = (_bit_rotate(temp_key_truncate, 64, RIGHT))
            # Drop right most two hex values
            for j in range(counter_truncate):
                for k in range(8):
                    temp_key_truncate = (_bit_rotate(temp_key_truncate, 64, RIGHT))
        

        # Update loop control variables and ret value
        add = temp_key_truncate & 0xFF                   # Truncate excess bits to keep the subkeys 32 bits
        ret.append(add)
        # ret.append(int.to_bytes(add, 1, "big").hex())    # Add to return list, represent in hex format for debuggin
        counter_truncate = (counter_truncate + 1) % 4    # Increase the amount of shifts needed to reach next key block
        counter_side_swap = (counter_side_swap + 1) % 24 # Increase the amount of checks before swapping halves

    # DEBUG USE ONLY
    """
    print(ret)  # Validate keystream
    print(f'Key After Stream: {int.to_bytes(temp_key, 8, "big").hex()}') # Validate it rotated completely through
    """
    # Return list of key blocks
    return ret

def _bit_rotate(key, key_len, dir):

    # Rotate left
    if (dir == LEFT):
        left_truncate = (2 ** key_len)-2    # Equivelant to 0xFFFF FFFF FFFF FFFE to drop the right most bit
        reg = ((key << 1) & left_truncate)  # Shift left, then drop the rightmost bit
        overflow = key >> (key_len - 1)     # Shift to catch the leftmost bit to put on the righthand bit slot

    # Rotate right
    if (dir == RIGHT):
        right_truncate = 2 ** (key_len - 1)                 # Equivelant to 0xEFFF FFFF FFFF FFFF FFFF to drop the leftmost bit
        reg = key >> 1                                      # Shift right, then drop the leftmost bit
        overflow = (key << (key_len - 1)) & right_truncate  # Shift to catch the rightmost bit to put on the lefthand bit slot
    
    # Bitwise OR to append the overflow bit to the dropped bit position
    return (reg|overflow)

def _split(arg):
    ret = []
    ret.append((arg >> 48) & 0xFFFF)
    ret.append((arg >> 32) & 0xFFFF)
    ret.append((arg >> 16) & 0xFFFF)
    ret.append((arg >> 0) & 0xFFFF)
    return ret