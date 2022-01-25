import pefile
pe = pefile.PE('crylock')




def config_decoder(injected_rsrc,dict_data):
	count = 1
	while (count < len(injected_rsrc)):
		sb = int(injected_rsrc[count-1])
		if sb == 1:
			new_offset = count + 1
			fa = injected_rsrc[new_offset-1:new_offset-1+4]
			print(chr(dict_data[int(fa,2)]),end="")
			count = new_offset + 4
		else:
			new_offset = count + 1
			fa = injected_rsrc[new_offset-1:new_offset -1 + 8]
			print(chr(int(fa,2)),end="")
			count = new_offset + 8

offset = 0x0
size = 0x0
for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
	for entry in rsrc.directory.entries:
		if entry.name is not None:
			if entry.name.__str__() == "DICT":
				offset = entry.directory.entries[0].data.struct.OffsetToData
				size = entry.directory.entries[0].data.struct.Size
				print(hex(offset), hex(size))
			if entry.name.__str__() == "EXTENATIONS":
				offset1 = entry.directory.entries[0].data.struct.OffsetToData
				size1 = entry.directory.entries[0].data.struct.Size
				print(hex(offset1), hex(size1))
			if entry.name.__str__() == "CONFIG":
				offset2 = entry.directory.entries[0].data.struct.OffsetToData
				size2 = entry.directory.entries[0].data.struct.Size
				print(hex(offset2), hex(size2))
			if entry.name.__str__() == "HTA":
				offset3 = entry.directory.entries[0].data.struct.OffsetToData
				size3 = entry.directory.entries[0].data.struct.Size
				print(hex(offset3), hex(size3))


ext_data = ""
config_dat = ""
hta_dat = ""
dict_data = pe.get_memory_mapped_image()[offset:offset+size]
config_data = pe.get_memory_mapped_image()[offset2:offset2+size2]
extentions_data = pe.get_memory_mapped_image()[offset1:offset1+size1]
hta_data = pe.get_memory_mapped_image()[offset3:offset3+size3]
for i in extentions_data[4:]:
	ext_data = ext_data + str(bin(i)[2:].zfill(8))
for i in config_data[4:]:
	config_dat = config_dat + str(bin(i)[2:].zfill(8))
for i in hta_data[4:]:
	hta_dat = hta_dat + str(bin(i)[2:].zfill(8))

print("--------------------------------------------------------")
config_decoder(config_dat,dict_data)
print("--------------------------------------------------------")
config_decoder(ext_data,dict_data)
print("--------------------------------------------------------")
config_decoder(hta_dat,dict_data)
print("--------------------------------------------------------")
