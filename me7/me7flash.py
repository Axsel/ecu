from utils.pattern import Pattern
from utils.maputils import TableReader, Table
from chipsets.c166.disasm import Disassembly
from . import eskonf
from .maps import cdkat, cdsls, cwdlsahk, catr, clrhk, kfkhfm, kfzw, snm16zuub, srl12zuub


class Me7Flash:
    def __init__(self, flash_binary):
        self.eskonf = {"version": None, "file_offset": -1, "bytes": None}

        self.disasm = Disassembly(flash_binary)

        #print(f"DPP0 0x{self.disasm._dpp0:02X}")
        #print(f"DPP1 0x{self.disasm._dpp1:02X}")
        #print(f"DPP2 0x{self.disasm._dpp2:02X}")
        #print(f"DPP3 0x{self.disasm._dpp3:02X}")

        # TODO detect 7.1 or 7.1.1 or 7.5

        # single cell maps
        self.found_vars = list()
        # axises
        self.found_axises = list()
        # multiple cell maps
        self.found_maps = list()

        return
    
    def find_vars(self):
        # needs me7.5 support
        print("[*] find_eskonf")
        if eskonf.find_eskonf(self):
            eskonf.print_eskonf(self)
        else: 
            print("[!] didnt find eskonf")

        # finds on most cases
        print("[*] find_cdkat")
        if not cdkat.find_cdkat(self):
            print("[!] didnt find cdkat")

        #
        print("[*] find_cdsls")
        if not cdsls.find_cdsls(self):
            print("[!] didnt find cdsls")

        #
        print("[*] find_cwdlsahk")
        if not cwdlsahk.find_cwdlsahk(self):
            print("[!] didnt find cwdlsahk")

        # 
        print("[*] find_catr")
        if not catr.find_catr(self):
            print("[!] didnt find catr")

        # 
        print("[*] find_clrhk")
        if not clrhk.find_clrhk(self):
            print("[!] didnt find clrhk")


        print("[+] found vars:")
        for m in self.found_vars:
            reader = TableReader(m, self)
            print("\t" + reader.table_name + " " + str(reader.table.cell.offset))
            print("\t" + str(reader.read_datacell_at(0)))

        return

    def find_maps(self):
        #mapfinder.find_generic_maps(self)

        # find some axises
        print("[*] find snm16zuub")
        if not snm16zuub.find_snm16zuub(self):
            print("[!] didnt find snm16zuub")

        #t = Table(None, [self.found_axises[0]])
        #r = TableReader(t, self)
        #for i in range(0, 16):
        #    print(r.read_axis_at("SNM16ZUUB", i))

        print("[*] find srl12zuub")
        if not srl12zuub.find_srl12zuub(self):
            print("[!] didnt find srl12zuub")

        #t = Table(None, [self.found_axises[1]])
        #r = TableReader(t, self)
        #for i in range(0, 12):
        #    print(r.read_axis_at("SRL12ZUUB", i))


        print("[*] find kfzw")
        c = kfzw.find_kfzw(self)
        if c is None:
            print("[!] didnt find kfzw")
        else:
            t = Table(
                c, 
                list(filter(lambda axis: axis.name == 'SRL12ZUUB', self.found_axises)) +
                list(filter(lambda axis: axis.name == 'SNM16ZUUB', self.found_axises))
            )
            self.found_maps.append(t)

            r = TableReader(t, self)
            r.print_table()
            

        print("[*] find kfzw2")
        c = kfzw.find_kfzw2(self)
        if c is None:
            print("[!] didnt find find_kfzw2")
        else:
            t = Table(
                c, 
                list(filter(lambda axis: axis.name == 'SRL12ZUUB', self.found_axises)) +
                list(filter(lambda axis: axis.name == 'SNM16ZUUB', self.found_axises))
            )
            self.found_maps.append(t)

            r = TableReader(t, self)
            r.print_table()            


        return
        print("[+] found maps:")
        for m in self.found_maps:
            reader = TableReader(m, self)
            print("\t" + reader.table_name + " " + str(reader.table.cell.offset))

        return



