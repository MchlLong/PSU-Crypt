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
    counter_truncate = 0    # Counter to truncate 'X' bytes where 'X' is two times the counter
    counter_side_swap = 0   # Counter to swap between right half of key and left half of key

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
        

        # Update loop control variables and ret value
        add = temp_key_truncate & 0xFF                   # Truncate excess bits to keep the subkeys 32 bits
        ret.append(int.to_bytes(add, 1, "big").hex())    # Add to return list
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
