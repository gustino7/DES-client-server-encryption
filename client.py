import socket

def DES_Encrypt(msg):
    plaintext_block_size = 8
    plaintext_initial_permutation = (2, 6, 3, 1, 4, 8, 5, 7)
    plaintext_expansion_permutation = (4, 1, 2, 3, 2, 3, 4, 1)
    substitution_box_0 =[[1, 0, 3, 2],
                         [3, 2, 1, 0],
                         [0, 2, 1, 3],
                         [3, 1, 3, 2]]
    substitution_box_1 =[[0, 1, 2, 3],
                         [2, 0, 1, 3],
                         [3, 0, 1, 0],
                         [2, 1, 0, 3]]
    right_half_permutation_box = (2, 4, 3, 1)
    inverse_initial_permutation = (4, 1, 3, 5, 7, 2, 8, 6)

    plaintext = msg.rstrip()
    key = 523
    subkeys = generate_subkeys(key)
    permuted_plaintext = []

    for i in plaintext :
        binary_plaintext = format(ord(i), "0{}b".format(plaintext_block_size))
        permuted_plaintext.append(__get_permuted_value(binary_plaintext, plaintext_initial_permutation))

    k = 0
    for key in subkeys :
        i = 0
        for block in permuted_plaintext :
            left_half = block[:4]
            right_half = block[4:]
            new_left_half = right_half

            right_half = __get_permuted_value(right_half, plaintext_expansion_permutation)
            temp = xor_operation(int(right_half, 2), int(key, 2))
            right_half = format(temp, "0{}b".format(len(block)))

            right_half = __perform_substitution(right_half[:4], substitution_box_0) + \
                            __perform_substitution(right_half[4:], substitution_box_1)
            
            right_half = __get_permuted_value(right_half, right_half_permutation_box)

            temp = xor_operation(int(right_half, 2), int(left_half, 2))
            new_right_half = format(temp, "0{}b".format(int(len(block)/2)))

            if (k == len(subkeys) - 1) :
                permuted_plaintext[i] = new_right_half + new_left_half
            else :
                permuted_plaintext[i] = new_left_half + new_right_half
            i += 1
        k += 1
    ciphertext = []
    for block in permuted_plaintext :
        ciphertext.append(__get_permuted_value(block, inverse_initial_permutation))

    result = "".join(ciphertext)
    return result

def generate_subkeys(key):
    key_size = 10
    subkey_initial_permutation = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
    subkey_compression_permutation = (6, 3, 7, 4, 8, 5, 10, 9)
    no_of_rounds = 16
    key_shift_values = (2, 1)
    key = format(key, "0{}b".format(key_size))
    permuted_key = __get_permuted_value(key, subkey_initial_permutation)
    all_subkeys = []

    for i in range(no_of_rounds) :
        left_half = permuted_key[:int(key_size/2)]
        right_half = permuted_key[int(key_size/2):]

        left_half = format(circular_left_shift(int(left_half, 2), key_shift_values[i%2], int(key_size/2)), \
                            "0{}b".format(int(key_size/2)))
        right_half = format(circular_left_shift(int(right_half, 2), key_shift_values[i%2], int(key_size/2)), \
                            "0{}b".format(int(key_size/2)))
        
        merged_halfs = left_half + right_half
        all_subkeys.append(__get_permuted_value(merged_halfs, subkey_compression_permutation))
        permuted_key = merged_halfs
    return all_subkeys

def __get_permuted_value(data, permutation) :
        permuted_value = []
        for i in permutation :
            permuted_value.append(data[i - 1])
        return("".join(permuted_value))

def circular_left_shift(num, shift_amount, size_of_shift_register) :
        binary_rep = "{0:0{1}b}".format(num, size_of_shift_register)
        shift_amount = shift_amount % size_of_shift_register
        ans = binary_rep[shift_amount:] + binary_rep[:shift_amount]
        return int(ans, 2)

def xor_operation(a, b) :
        return a ^ b

def __perform_substitution(data, sub_box) :
        row_number = int(data[0] + data[3], 2)
        column_number = int(data[1] + data[2], 2)
        return format(sub_box[row_number][column_number], "02b")

def run_client():
    # create a socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_ip = "192.216.1.2"  # replace with the server's IP address
    server_port = 8000  # replace with the server's port number
    # establish connection with server
    client.connect((server_ip, server_port))

    while True:
        # input message and send it to the server
        msg = input("Enter message: ")
        cipertext = DES_Encrypt(msg).encode("utf-8")[:1024]
        client.send(cipertext)

        # receive message from the server
        response = client.recv(1024)
        response = response.decode("utf-8")

        # if server sent us "closed" in the payload, we break out of the loop and close our socket
        if response.lower() == "closed":
            break

        print(f"Received: {response}")

    # close client socket (connection to the server)
    client.close()
    print("Connection to server closed")

run_client()
