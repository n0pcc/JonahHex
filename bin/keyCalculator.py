import pefile

pe = pefile.PE("JonahHex.exe")

ccCount = 0
text_section = pe.get_data(pe.sections[0].VirtualAddress, pe.sections[0].Misc_VirtualSize)

for byte in text_section:
	if byte == '\xCC':
		ccCount += 1
	if ccCount % 22 == 0:
		ccCount *= ccCount + 42
	ccCount %= 0x100

print "AddressOfEntryPoint: " + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print "DES key: " + 8*hex(ccCount)[2:]