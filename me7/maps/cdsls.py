from utils.pattern import Pattern
from utils.maputils import Table, Cell

# CDSLS 
# size: byte
# attempts to find CDSLS
# used for SAI (secondary air intake) diagnosis

def find_cdsls(me7):
    cdsls_sig = Pattern(
        [0xD7, 0x40, 0, 0, 0xC2, 0xF4, 0, 0, 0x68, 0x41, 0x2D, 0x05, 0xE6, 0xF4, 0x00, 0x04, 0x74, 0xF4], 
        "xx??xx??xxxxxxxxxx"
    )
    cdsls_pattern = cdsls_sig.scan(me7.disasm.orig_bin)        
    if len(cdsls_pattern) <= 0:
        return False
    
    word_offset = cdsls_pattern[0] + 6
    dpp_offset = cdsls_pattern[0] + 2

    word_offset = me7.disasm.read_word(word_offset)
    dpp = me7.disasm.read_word(dpp_offset)

    file_offset = me7.disasm.offset_to_file_offset(word_offset, dpp)

    cdsls_cell = Cell("CDSLS", file_offset)
    cdsls_table = Table(cdsls_cell, [])

    me7.found_vars.append(cdsls_table)
    return True