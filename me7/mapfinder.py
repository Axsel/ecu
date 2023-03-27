# generic mapfinder
# uses generic table lookup signatures to identify calls to different table lookups

from utils.pattern import Pattern
from chipsets.c166.disasm import Disassembly

def find_generic_maps(me7):
    found_tables = 0

    # general idea here would be to:
    # get a hit,
    # look back within the function (disassemble in reverse and make sure we dont hit ret or smth???)
    # try and find extp to see what the dpp is set to
    # then calculate the location of map table dpp * page size + whatever is set to r12
    # think this is all mapped to 0x810000 in memory, at least in winols the file offset is + 0x10000
    """
    0xE6, 0xFC, XXXX, XXXX,  // mov     r12, #(MAP_X_NUM - ROM_MAP_REGION_818000)   <--- * This is the MAP XXX
    0xE6, 0xFD, XXXX, XXXX,  // mov     r13, #XXXXh
    0xC2, 0xFE, XXXX, XXXX,  // movbz   r14, XXXX
    // 0xC2, 0xFF, XXXX, XXXX,  // movbz   r15, XXXX
    0xDA, XXXX, XXXX, XXXX,  // calls   XXXXh, Lookup_Table_Data ; References a lookup tableAE
    """
    lookup_results = Pattern(
        [0xE6, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xC2, 0xFE, 0, 0, 0xDA, 0, 0, 0], 
        "xx??xx??xx??x???"
    ).scan(me7.disasm._orig_bin)
    found_tables += len(lookup_results)
    for r in lookup_results:
        r12 = me7.disasm.read_word(r + 2)
        print(f"gen_lookup_1 0x{r:04X} {r12:02X}")


    """ 
    0x88, 0x50,              // mov     [-r0], r5
    0xE6, 0xFC, XXXX, XXXX,  // mov     r12, #XXXX 	[+14]<---- *table   +14
    0xE6, 0xFD, XXXX, XXXX,  // mov     r13, #XXXXh    [+18]<---- *segment +18
    0xE6, 0xFE, XXXX, XXXX,  // mov     r14, #XXXX		[+22]<---- *table   +24
    0xE6, 0xFF, XXXX, XXXX,  // mov     r15, #XXXXh	[+26]<---- *segment +28
    0xDA, XXXX, XXXX, XXXX,  // calls   XXXXh, Lookup_XXXX
    0x08, 0x04               // add     r0,  #4    
    """
    lookup_results = Pattern(
        [0x88, 0x50, 0xE6, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xE6, 0xFE, 0, 0, 0xE6, 0xFF, 0, 0, 0xDA, 0, 0, 0, 0x08, 0x04], 
        "xxxx??xx??xx??xx??x???xx"
    ).scan(me7.disasm._orig_bin)
    found_tables += len(lookup_results)
    for r in lookup_results:
        r12 = me7.disasm.read_word(r + 4)
        r14 = me7.disasm.read_word(r + 12)
        print(f"gen_lookup_2 0x{r:04X} {r12:02X} {r14:02X}")


    """
    0xE6, 0xF4, XXXX, XXXX,  // mov     r4, #XXXX_DATA_TBL 	; Table Data                  [+2]
    0xE6, 0xF5, XXXX, XXXX,  // mov     r5, #XXXXh				; Segment                     [+6]
    0x88, 0x50,              // mov     [-r0], r5
    0x88, 0x40,              // mov     [-r0], r4
    0xE6, 0xF4, XXXX, XXXX,  // mov     r4, #XXXX_Y_AXIS 		; Table Y Axis Data           [+14]
    0xE6, 0xF5, XXXX, XXXX,  // mov     r5, #XXXXh				; Segment                     [+18]
    0x88, 0x50,              // mov     [-r0], r5
    0x88, 0x40,              // mov     [-r0], r4
    0xD7, 0x40, XXXX, XXXX,  // extp    #XXXXh, #1				; Segment                     [+26]
    0xC2, 0xFC, XXXX, XXXX,  // movbz   r12, XXXX_X_NUM			; Table X Number of Items [+30]
    0xE6, 0xFD, XXXX, XXXX,  // mov     r13, #XXXX_X_AXIS 		; Table X Axis Data           [+34]
    0xE6, 0xFE, XXXX, XXXX,  // mov     r14, #XXXXh				; Segment                 [+38]
    0xD7, 0x40, XXXX, XXXX,  // extp    #XXXXh, #1				; Segment                     [+42]
    0xC2, 0xFF, XXXX, XXXX,  // movbz   r15, XXXX_Y_NUM			; Table Y Number of Items [+46]
    0xDA, XXXX, XXXX, XXXX,  // calls   XXXXh, XXXX_Lookup_func	; do the lookup    
    """
    lookup_results = Pattern(
        [0xE6, 0xF4, 0, 0, 0xE6, 0xF5, 0, 0, 0x88, 0x50, 0x88, 0x40, 
        0xE6, 0xF4, 0, 0, 0xE6, 0xF5, 0, 0, 0x88, 0x50, 0x88, 0x40, 
        0xD7, 0x40, 0, 0, 0xC2, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xE6, 
        0xFE, 0, 0, 0xD7, 0x40, 0, 0, 0xC2, 0xFF, 0, 0, 0xDA, 0, 0, 0], 
        "xx??xx??xxxxxx??xx??xxxxxx??xx??xx??xx??xx??xx??x???"
    ).scan(me7.disasm._orig_bin)
    found_tables += len(lookup_results)
    for r in lookup_results:
        r4 = me7.disasm.read_word(r + 4)
        print(f"gen_lookup_3 0x{r:04X} {r4:02X}")


    """
    0xE6, 0xFC, XXXX, XXXX,  // mov     r12, #(MAP_X_NUM - ROM_MAP_REGION_818000)   <--- * This is the MAP XXX
    0xE6, 0xFD, XXXX, XXXX,  // mov     r13, #XXXXh
    0xF2, 0xFE, XXXX, XXXX,  // mov     r14, word_XXXX
    0xF2, 0xFF, XXXX, XXXX,  // mov     r14, word_XXXX
    0xDA, XXXX, XXXX, XXXX,  // calls   XXXXh, Lookup_Table_Data ; References a lookup tableAE
    0xF6, 0xF4, XXXX, XXXX,  // mov     word_XXXX, r4    
    """
    lookup_results = Pattern(
        [0xE6, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xF2, 0xFF, 0, 0, 0xDA, 0, 0, 0, 0xF6, 0xF4, 0, 0], 
        "xx??xx??xx??xx??x???xx??"
    ).scan(me7.disasm._orig_bin)
    found_tables += len(lookup_results)
    for r in lookup_results:
        r12 = me7.disasm.read_word(r + 2)
        print(f"gen_lookup_4 0x{r:04X} {r12:02X} ")

    print("tables found: " + str(found_tables))    
    return

