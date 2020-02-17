# Michael Long
# CS485
# Project #1: Implementing "PSU-CRYPT"
# PSU-CRYPT

# Constants
LEFT = 0
RIGHT = 1

def encrypt(data, key):
    # Encrypt
    pass

def decrypt(data, key):
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
    counter_truncate = 0
    counter_side_swap = 0

    for i in range(192):

        temp_key = (_bit_rotate(temp_key, 64, LEFT))    # Rotate Left bit
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
        

        # Update stuff
        add = temp_key_truncate & 0xFF
        ret.append(int.to_bytes(add, 1, "big").hex())
        counter_truncate = (counter_truncate + 1) % 4
        counter_side_swap = (counter_side_swap + 1) % 24

    # Work before return
    print(ret)
    print(f'Key After Stream: {int.to_bytes(temp_key, 8, "big").hex()}')
    return ret

def _bit_rotate(key, key_len, dir):

    # For "Left Rotation"
    # Placehold overflow bits
    if (dir == LEFT):
        # Leftmost bit truncated
        left_truncate = (2 ** key_len)-2
        reg = ((key << 1) & left_truncate)
        overflow = key >> (key_len - 1)

    if (dir == RIGHT):
        right_truncate = 2 ** (key_len - 1)
        reg = key >> 1
        overflow = (key << (key_len - 1)) & right_truncate
    
    # OR the two (Normal Bytes and a bunch of 0's with a 1 or 0)
    return (reg|overflow)
