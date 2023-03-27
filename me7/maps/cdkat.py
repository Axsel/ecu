from utils.pattern import Pattern
from utils.maputils import Table, Cell

# CDKAT 
# size: byte
# attempts to find CDKAT

def find_cdkat(me7):
    cdkat_sig = Pattern(
        [0xD7, 0x40, 0, 0, 0xC2, 0xF4, 0, 0, 0x68, 0x41, 0x2D, 0x05, 0xE6, 0xF4, 0x00, 0x01, 0x74, 0xF4], 
        "xx??xx??xxxxxxxxxx"
    )
    cdkat_pattern = cdkat_sig.scan(me7.disasm.orig_bin)        
    if len(cdkat_pattern) <= 0:
        return False
    
    word_offset = cdkat_pattern[0] + 6
    dpp_offset = cdkat_pattern[0] + 2

    word_offset = me7.disasm.read_word(word_offset)
    dpp = me7.disasm.read_word(dpp_offset)

    file_offset = me7.disasm.offset_to_file_offset(word_offset, dpp)

    cdkat_cell = Cell("CDKAT", file_offset)
    cdkat_table = Table(cdkat_cell, [])

    me7.found_vars.append(cdkat_table)
    return True