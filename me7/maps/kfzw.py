from utils.pattern import Pattern
from utils.maputils import Table, Cell, Sign

# KFZW and KFZW2 and axises SNM16ZUUB and SRL12ZUUB if not found already
# size: SNM16ZUUB x SRL12ZUUB
# attempts to find KFZW and KFZW2

def find_kfzw(me7):
    # TODO might need some more accuracy, also returns another map ref, so is prone to false positives!
    kfzw_sig = Pattern(
        [0xE6, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xF2, 0xFF, 0, 0, 0xDA, 0x00, 0xB8, 0x78] + ([0] * 18) + [0xE6, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xF2, 0xFF, 0, 0, 0xDA, 0x00, 0xB8, 0x78], # XX70 46 F9 7F 00 XX20 46 F9 80 FF], 
        "xx??xx??xx??xx??xxxx" + ''.join(['?'] * 18) + "xx??xx??xx??xx??xxxx"
    )
    kfzw_pattern = kfzw_sig.scan(me7.disasm.orig_bin)
    if len(kfzw_pattern) <= 0:
        return None
    
    word_offset = kfzw_pattern[0] + 40
    word_offset = me7.disasm.read_word(word_offset)
    file_offset = me7.disasm.offset_to_file_offset(word_offset)

    # just testing
    #for i in range(0, 12*16):
    #    read = me7.disasm.read_byte_signed(file_offset+i)
    #    print(read * 0.75)
    c = Cell("KFZW", file_offset, element_size=1, conversion_factor=0.75, sign=Sign.Signed)
    return c


def find_kfzw2(me7):
    # TODO might need some accuracy, prone to false positives, we need to introduce proper wildcard system to pattern scan
    kfzw2_sig = Pattern(
        [0x0D, 0x2F, 0xE6, 0xFC, 0, 0, 0xE6, 0xFD, 0, 0, 0xF2, 0xFE, 0, 0, 0xF2, 0xFF, 0, 0, 0xDA, 0x00, 0xB8, 0x78] + ([0] * 16) + [0xE6, 0xFC, 0, 0],
        "xxxx??xx??xx??xx??xxxx" + ''.join(['?'] * 16) + "xx??"
    )
    kfzw2_pattern = kfzw2_sig.scan(me7.disasm.orig_bin)
    if len(kfzw2_pattern) <= 0:
        return None
    
    word_offset = kfzw2_pattern[0] + 4
    word_offset = me7.disasm.read_word(word_offset)
    file_offset = me7.disasm.offset_to_file_offset(word_offset)

    c = Cell("KFZW2", file_offset, element_size=1, conversion_factor=0.75, sign=Sign.Signed)
    return c

"""
<?xml version="1.0" encoding="UTF-8"?>
<map xmlns="http://prj-tuning.com/mapdef" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://prj-tuning.com/mapdef mapdef.xsd ">
	<id>KFZW</id>
	<pattern>E6 FC XX XX E6 FD XX XX F2 FE XX XX F2 FF XX XX DA 00 B8 78 XX18 E6 FC MMXX XX E6 FD XX XX F2 FE XX XX F2 FF XX XX DA 00 B8 78 XX70 46 F9 7F 00 XX20 46 F9 80 FF</pattern>
	<conversion>
		<factor>0.75</factor>
		<signed>true</signed>
	</conversion>
	<rowAxis>
		<id>SNM16ZUUB</id>
	</rowAxis>
	<colAxis>
		<id>SRL12ZUUB</id>
	</colAxis>
</map>
"""


""" 
 
unsigned char needle_ZWGRU[] = {
	0x88, 0x90,                                   // mov     [-r0], r9
	0x88, 0x70,                                   // mov     [-r0], r7
	0x88, 0x60,                                   // mov     [-r0], r6
	0x28, 0x02,                                   // sub     r0, #2
	0xF3, 0xF8, XXXX, XXXX,                       // movb    rl4, fnwue
	0x47, 0xF8, 0xFF, 0x00,                       // cmpb    rl4, #0FFh
	0x3D, 0x10,                                   // jmpr    cc_NZ, lookup_KFZW
	0xE6, 0xFC, XXXX, XXXX,                       // mov     r12, #KFZW2_CELLS ; KFZW2 : Znndwinkelkennfeld Variante 2 [ZWGRU]
	0xE6, 0xFD, XXXX, XXXX,                       // mov     r13, #SRL12ZUUB
	0xF2, 0xFE, XXXX, XXXX,                       // mov     r14, esst_snm16zuub ; esst_snm16zuub :  [SSTB ZWGRU ZWMIN]
	0xF2, 0xFF, XXXX, XXXX,                       // mov     r15, esst_srl12zuub ; esst_srl12zuub :  [SSTB ZWGRU ZWMIN]
	0xDA, XXXX, XXXX, XXXX,                       // calls   0, Map_Lookup2D ; 2D Lookup Word Arguments usually Spark related
	0xF1, 0xE8,                                   // movb    rl7, rl4
	0xF7, 0xF8, XXXX, XXXX,                       // movb    zwnws, rl4      ; zwnws : Grundznndwinkel mit Berncksichtigung von Nockenwellensteuerung [ZWGRU]
	0xE1, 0x0C,                                   // movb    rl6, #0
	0xEA, XXXX, XXXX, XXXX,                       // jmpa    cc_UC, loc_XXXX
	0xF3, 0xF8, XXXX, XXXX,                       // movb    rl4, fnwue      ; fnwue ZWGRU]
	0x3D, 0x0F,                                   // jmpr    cc_NZ, lookup_KFZW2
	0xE6, 0xFC, XXXX, XXXX,                       // mov     r12, #KFZW_CELLS ; KFZW : Znndwinkelkennfeld [ZWGRU]
	0xE6, 0xFD, XXXX, XXXX,                       // mov     r13, #SRL12ZUUB
	0xF2, 0xFE, XXXX, XXXX,                       // mov     r14, esst_snm16zuub ; esst_snm16zuub :  [SSTB ZWGRU ZWMIN]
	0xF2, 0xFF, XXXX, XXXX,                       // mov     r15, esst_srl12zuub ; esst_srl12zuub :  [SSTB ZWGRU ZWMIN]
	0xDA, XXXX, XXXX, XXXX,                       // calls   0, Map_Lookup2D ; 2D Lookup Word Arguments usually Spark related
	0xF1, 0xC8,                                   // movb    rl6, rl4
	0xF7, 0xF8, XXXX, XXXX,                       // movb    zwnws, rl4      ; zwnws : Grundznndwinkel mit Berncksichtigung von Nockenwellensteuerung [ZWGRU]
	0xE1, 0x0E                                    // movb    rl7, #0
};
"""