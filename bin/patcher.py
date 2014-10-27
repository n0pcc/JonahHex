import pefile

pe = pefile.PE("JonahHex.exe")

# Patching the jumps.
jmp_tls_1 = [0x00001703, 0x0000170C, 0x000020A6]
jmp_main = [0x000021AC, 0x00002830]

xor_tls_1 = [0x8, 0x40, 0x200]
xor_main = [0x2fe095ad, 0x1660d216]

for i, address in enumerate(jmp_tls_1):
	value = pe.get_dword_at_rva(address);
	pe.set_dword_at_rva(address, value ^ xor_tls_1[i])

for i, address in enumerate(jmp_main):
	value = pe.get_dword_at_rva(address);
	pe.set_dword_at_rva(address, value ^ xor_main[i])

# Patching the ciphertext checks.
des_intermediate_addr = [0x00002F3A, 0x00002F47]
des_output_addr = [0x00002537, 0x00002544]

des_intermediate_value = [0xB3143B79, 0x19A2E3D5]
des_output_value = [0xEEC5860E, 0x8E0A2C1F]

cipherxor = 0x41424344

for i in xrange(0, 2):
	pe.set_dword_at_rva(des_intermediate_addr[i], des_intermediate_value[i] ^ cipherxor)
	print "DES intermediate value " + str(i) + ": " + hex(des_intermediate_value[i] ^ cipherxor)[:-1]
	pe.set_dword_at_rva(des_output_addr[i], des_output_value[i] ^ cipherxor)
	print "DES output value " + str(i) + ": " + hex(des_output_value[i] ^ cipherxor)[:-1]

pe.write(filename="JonahHex.exe")