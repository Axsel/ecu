from utils.pattern import Pattern
from utils.maputils import Table, Cell, Axis, Sign

# axis SNM16ZUUB used by KFZW for example

def find_snm16zuub(me7):
    snm16zuub_sig = Pattern(
        [0xDA, 0x00, 0, 0, 0xF6, 0xF4, 0, 0, 0xE6, 0xFC, 0, 0x00, 0xC2, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xDA, 0x00, 0, 0, 0xF6, 0xF4, 0, 0, 0xE6, 0xFC, 0, 0, 0xC2, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xDA, 0x00, 0, 0, 0xF6, 0xF4, 0, 0, 0xE6, 0xFC, 0, 0], 
        "xx??xx??xx?xxx??xx??xx??xx??xx??xx??xx??xx??xx??xx??"
    )
    snm16zuub_pattern = snm16zuub_sig.scan(me7.disasm.orig_bin)
    if len(snm16zuub_pattern) > 0:
        word_offset = snm16zuub_pattern[0] + 50
    else:
        snm16zuub_sig = Pattern(
            [0xDA, 0x00, 0, 0, 0xF6, 0xF4, 0, 0, 0xE6, 0xFC, 0, 0, 0xC2, 0xFD, 0, 0, 0xDA, 0x00, 0, 0, 0xF6, 0xF4, 0, 0, 0xE6, 0xFC, 0, 0, 0xC2, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xDA], 
            "xx??xx??xx??xx??xx??xx??xx??xx??xx??x"
        )
        snm16zuub_pattern = snm16zuub_sig.scan(me7.disasm.orig_bin)        
        if len(snm16zuub_pattern) > 0:
            word_offset = snm16zuub_pattern[0] + 26
        else:
            return False    

    word_offset = me7.disasm.read_word(word_offset)
    file_offset = me7.disasm.offset_to_file_offset(word_offset)
    axis_len = me7.disasm.read_word(file_offset)

    # table content start
    file_offset += 2

    snm16zuub_axis = Axis("SNM16ZUUB", file_offset, element_size=2, element_count=axis_len, conversion_factor=0.25, sign=Sign.Unsigned)
    me7.found_axises.append(snm16zuub_axis)

    return True