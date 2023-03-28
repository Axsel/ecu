from utils.pattern import Pattern, PatternWildcard
from utils.maputils import Table, Cell, Sign, Axis, TableReader

# MLHFM
# size: 1x512
# maf scaling

def find_mlhfm(me7):
	mlhfm_sig = PatternWildcard(
		[0x5C, 0x14, 0xD4, 0x54] + [0, 0, 0, 0, 0, 0, 0]+ [0xE6, 0, 0xFF, 0xFF, 0xF0], 
		"xxxx" + "*******" + "x?xxx")
	mlhfm_pattern = mlhfm_sig.scan(me7.disasm.orig_bin)
	if len(mlhfm_pattern) <= 0:
		return False

	word_offset = mlhfm_pattern[0] + 4
	word_offset = me7.disasm.read_word(word_offset)
	file_offset = me7.disasm.offset_to_file_offset(word_offset)
	
	print(f"MLHFM 0x{file_offset:X}")
	a = Axis("MLHFM", file_offset, 2, 512, 0.1)
	me7.found_axises.append(a)

	#t = Table(None, [a])
	#rdr = TableReader(t, me7)
	#for i in range(0, 512):
	#	print(float(rdr.read_axis_at("MLHFM", i))-200.0)
	#print("subtract MLOFS (200 for Bosch MAF)")
	
	return True
	