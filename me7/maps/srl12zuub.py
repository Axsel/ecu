from utils.pattern import Pattern
from utils.maputils import Table, Cell, Axis, Sign

# axis SRL12ZUUB used by KFZW for example

def find_srl12zuub(me7):
    # TODO might need some accuracy, prone to false positives, we need to introduce proper wildcard system to pattern scan
    srl12zuub_sig = Pattern(
        [0xE6, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xF2, 0xFF, 0, 0, 0xDA, 0x00, 0xB8, 0x78] + ([0] * 18) + [0xE6, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xF2, 0xFF, 0, 0, 0xDA, 0x00, 0xB8, 0x78], 
        "xx??xx??xx??xx??xxxx" + ''.join(['?'] * 18) + "xx??xx??xx??xx??xxxx"
    )
    frl12zuub_pattern = srl12zuub_sig.scan(me7.disasm.orig_bin)
    if len(frl12zuub_pattern) <= 0:
        return False

    word_offset = frl12zuub_pattern[0] + 44

    word_offset = me7.disasm.read_word(word_offset)
    file_offset = me7.disasm.offset_to_file_offset(word_offset)

    axis_len = me7.disasm.read_word(file_offset)


    # table content start
    file_offset += 2

    srl12zuub = Axis("SRL12ZUUB", file_offset, element_size=2, element_count=axis_len, conversion_factor=0.023438, sign=Sign.Unsigned)
    me7.found_axises.append(srl12zuub)

    return True