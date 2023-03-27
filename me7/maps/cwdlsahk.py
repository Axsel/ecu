from utils.pattern import Pattern
from utils.maputils import Table, Cell

# CWDLSAHK 
# size: byte (different bits set different checks)
# attempts to find CWDLSAHK
# used for secondary O2 (post cat) diagnosis

def find_cwdlsahk(me7):
    cwdlsahk_sig = Pattern(
        [0xE6, 0xFC, 0, 0, 0xDA, 0, 0, 0, 0x08, 0x02, 0xD7, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0x3D, 0x04], 
        "xx??x???xxxx????????xx"
    )
    cwdlsahk_pattern = cwdlsahk_sig.scan(me7.disasm.orig_bin)        
    if len(cwdlsahk_pattern) <= 0:
        return False
    
    word_offset = cwdlsahk_pattern[0] + 16
    dpp_offset = cwdlsahk_pattern[0] + 12

    word_offset = me7.disasm.read_word(word_offset)
    dpp = me7.disasm.read_word(dpp_offset)

    file_offset = me7.disasm.offset_to_file_offset(word_offset, dpp)

    cwdlsahk_cell = Cell("CWDLSAHK", file_offset)
    cwdlsahk_table = Table(cwdlsahk_cell, [])

    me7.found_vars.append(cwdlsahk_table)
    return True