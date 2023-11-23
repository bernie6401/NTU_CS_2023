root = "./Reverse/hw2_r11921a16/src/Banana Donut Verifier/"
root = "./"
input_0x0 = open(root + 'user_input_all_0.mem', 'rb').read()

real_key = open(root + 'real_key.mem', 'rb').read()
# flag_file = open(root + 'flag.mem', 'wb')

flag = b''
for i in range(len(real_key)):
    flag += bytes([real_key[i] ^ input_0x0[i]])

# flag_file.write(flag)
# flag_file.close()
print("Exchange Flag is: " + flag.decode())