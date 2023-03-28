from utils.pattern import Pattern
from utils.maputils import Table, Cell

# MLOFS 
# size: word
# attempts to find CATR (used for egt disable - disables ATR )

def find_mlofs(me7):
    word_offset = 0
    mlofs_sig = Pattern(
        [0xE0, 0, 0xF2, 0, 0, 0, 0xE0, 0, 0x20, 0, 0x30, 0, 0xF2], 
        "x?x???x?x?x?x"
    )
    mlofs_pattern = mlofs_sig.scan(me7.disasm.orig_bin)        
    if len(mlofs_pattern) <= 0:
        mlofs_sig = Pattern(
            [0x5C, 0, 0x70, 0, 0xF6, 0, 0, 0, 0xF2, 0, 0, 0, 0x22, 0, 0, 0, 0x8D, 0x04], 
            "x?x?x???x???x???xx"
        )
        mlofs_pattern = mlofs_sig.scan(me7.disasm.orig_bin)         
        if len(mlofs_pattern) <= 0:
            return False
        else:
            word_offset = mlofs_pattern[0] + 14
    else:
        word_offset = mlofs_pattern[0] + 4

    word_offset = me7.disasm.read_word(word_offset)
    file_offset = me7.disasm.offset_to_file_offset(word_offset)

    mlofs_cell = Cell("MLOFS", file_offset)
    mlofs_table = Table(mlofs_cell, [])

    me7.found_vars.append(mlofs_table)
    return True