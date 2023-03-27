from utils.pattern import Pattern
from utils.maputils import Table, Cell

# CLRHK 
# size: byte
# attempts to find CLRHK (used for post cat o2 based control for lambda correction)
# from wiki - Code word for Lambda - Bit 0 is Control post cat on/off. Set bit 2 and 0, clear bit 3 to disable; i.e. set from 72 (0x48/01001000b) to 5 (00000101b)

def find_clrhk(me7):
    clrhk_sig = Pattern(
        [0x08, 0x04, 0xF7, 0xF8, 0, 0, 0xC2, 0xF4, 0, 0, 0x66, 0xF4, 0x08, 0x00], 
        "xxxx??xx??xxxx"
    )
    clrhk_pattern = clrhk_sig.scan(me7.disasm.orig_bin)        
    if len(clrhk_pattern) <= 0:
        return False
    
    word_offset = clrhk_pattern[0] + 8

    word_offset = me7.disasm.read_word(word_offset)

    file_offset = me7.disasm.offset_to_file_offset(word_offset)

    clrhk_cell = Cell("CLRHK", file_offset)
    clrhk_table = Table(clrhk_cell, [])

    me7.found_vars.append(clrhk_table)
    return True