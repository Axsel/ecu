import struct 

from chipsets.c166.arch_c166 import DisasmInstruction, INS_MAX_LEN, ROM_MAP_START_ADDRESS, MEM_PAGE_SIZE
from utils.pattern import Pattern

# holds the mapped view of the flash binary
class Disassembly:
    def __init__(self, bin):
        self.orig_bin = bin

        # use common default vars in case we cant detect
        self._dpp0 = 0x204 
        self._dpp1 = 0x205 
        self._dpp2 = 0xE0
        self._dpp3 = 0x03

        # TODO in some cases (ibiza, phaeton) this yields in multiple results where dpp's are set in group, first one has dpp0 of 0x0
        # mov dpp0, xxxx
        # mov dpp1, xxxx
        # mov dpp2, xxxx
        # mov dpp3, xxxx
        dpp_sig = Pattern(
            [0xE6, 0x00, 0, 0, 0xE6, 0x01, 0, 0, 0xE6, 0x02, 0, 0, 0xE6, 0x03, 0, 0], 
            "xx??xx??xx??xx??")
        dpp_pattern = dpp_sig.scan(self.orig_bin)
        
        if len(dpp_pattern) > 0:
            addr = dpp_pattern[0]
            temp_dpp = self.read_word(addr + 2)
            if temp_dpp != 0:
                self._dpp0 = temp_dpp
            temp_dpp = self.read_word(addr + 6)
            if temp_dpp != 0:
                self._dpp1 = temp_dpp
            temp_dpp = self.read_word(addr + 10)
            if temp_dpp != 0:
                self._dpp2 = temp_dpp
            temp_dpp = self.read_word(addr + 14)
            if temp_dpp != 0:
                self._dpp3 = temp_dpp                

    # map word from bin to offset in file, account paging
    def offset_to_file_offset(self, offset, dpp=None):
        if dpp is None:
            dpp = self._dpp0
        return (dpp * MEM_PAGE_SIZE - ROM_MAP_START_ADDRESS) + offset 

    def offset_to_rom_offset(self, offset):
        return offset + ROM_MAP_START_ADDRESS

    def read_word(self, offset):
        return struct.unpack('<H', bytes(self.orig_bin[offset:offset+2]))[0]

    def read_word_signed(self, offset):
        return struct.unpack('<h', bytes(self.orig_bin[offset:offset+2]))[0]

    def read_word_big_endian(self, offset):
        return struct.unpack('>H', bytes(self.orig_bin[offset:offset+2]))[0]

    def read_byte(self, offset):
        return struct.unpack('<B', bytes(self.orig_bin[offset:offset+1]))[0]

    def read_byte_signed(self, offset):
        return struct.unpack('<b', bytes(self.orig_bin[offset:offset+1]))[0]        

    def read_byte_big_endian(self, offset):
        return struct.unpack('>B', bytes(self.orig_bin[offset:offset+1]))[0]

    def get_instruction_len(self, offset):
        ins = self.orig_bin[offset:offset+INS_MAX_LEN]
        return DisasmInstruction(ins).get_len()

    def get_instruction_name(self, offset):
        ins = self.orig_bin[offset:offset+INS_MAX_LEN]
        return DisasmInstruction(ins).get_name()



"""
# mov dpp0, xxxx
# mov dpp1, xxxx
# mov dpp2, xxxx
# mov dpp3, xxxx
dpp_pattern = Pattern([0xE6, 0x00, 0, 0, 0xE6, 0x01, 0, 0, 0xE6, 0x02, 0, 0, 0xE6, 0x03, 0, 0], "xx??xx??xx??xx??")
dpp_pats = dpp_pattern.scan(hexdata)
print(dpp_pats)
instr = DisasmInstruction(hexdata[dpp_pats[0]:dpp_pats[0]+INS_MAX_LEN])
print(instr.get_name())
"""
"""
ip = 0
while True:
    print(f"IP: 0x{ip:X}")

    curbytes = hexdata[ip:ip+INS_MAX_LEN]

    instr = DisasmInstruction(curbytes)

    opcode = instr.get_opcode()
    name = instr.get_name()
    inslen = instr.get_len()
    insbytes = instr.read_bytes()

    print(f"0x{opcode:02X} {name} {insbytes} ({inslen})")

    ip += instr.get_len()
"""