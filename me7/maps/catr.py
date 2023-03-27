from utils.pattern import Pattern
from utils.maputils import Table, Cell

# CATR 
# size: byte
# attempts to find CATR (used for egt disable - disables ATR )

def find_catr(me7):
    catr_sig = Pattern(
        [0xD7, 0x40, 0, 0, 0xF3, 0xF8, 0, 0, 0x69, 0x81, 0x2D, 0x02, 0x6F, 0x88, 0x0D, 0x01], 
        "xx??xx??xxxxxxxx"
    )
    catr_pattern = catr_sig.scan(me7.disasm.orig_bin)        
    if len(catr_pattern) <= 0:
        return False
    
    word_offset = catr_pattern[0] + 6
    dpp_offset = catr_pattern[0] + 2

    word_offset = me7.disasm.read_word(word_offset)
    dpp = me7.disasm.read_word(dpp_offset)

    file_offset = me7.disasm.offset_to_file_offset(word_offset, dpp)

    catr_cell = Cell("CATR", file_offset)
    catr_table = Table(catr_cell, [])

    me7.found_vars.append(catr_table)
    return True