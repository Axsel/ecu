from utils.pattern import Pattern
from chipsets.c166.disasm import Disassembly

# ESKONF
# size 13 || 7 bytes
# attempts to find ESKONF using heuristics

def print_eskonf(me7):
    # parse and print eskonf

    # 00 installed
    # 10 special case
    # 11 not installed
    # 
    # me7.1(.1) 13 bytes
    # me7.5 7 bytes
    # https://s4wiki.com/wiki/Tuning#ESKONF

    if me7.eskonf["version"] is None:
        return
    
    if me7.eskonf["version"] in ["me7.1", "me7.1.1"]:
        # HSH and HSH2 (Rear O2 sensor heater) at [5][0] bitpair and [6][2] respectively
        hsh_banks = ["SKIP", "SKIP"]
        bits = ""
        for idx, b in enumerate(me7.eskonf["bytes"]):
            bitrow = "{0:08b}".format(b)
            bits += f"{idx}:\t"
            for i in range(0, len(bitrow), 2):
                # little endian
                #pair = bitrow[i:i+2][::-1]
                pair = bitrow[i:i+2]
                bits += pair + " "

                if idx == 5 and i == 0:
                    if pair == "00":
                        hsh_banks[0] = "INSTALLED"
                    elif pair == "11":
                        hsh_banks[0] = "SKIP"
                    else: 
                        hsh_banks[0] = "SPECIAL TREATMENT"
                if idx == 6 and i == 2*2:
                    if pair == "00":
                        hsh_banks[1] = "INSTALLED"
                    elif pair == "11":
                        hsh_banks[1] = "SKIP"                            
                    else: 
                        hsh_banks[1] = "SPECIAL TREATMENT"                            
            bits += "\n"
        print(bits)
        print("Rear O2 sensor: " + str(hsh_banks))

    # TODO handle me7.5
    #if me7.eskonf["vers"]

def find_eskonf(me7):
    # TODO implement strat based on me7x version

    found_eskonf = {
        "version": None,
        "file_offset": -1,
        "bytes": None,
    }

    # A3 vr6 (7.1)          (0C F0 BF FC 00 03 F3 FE AA FA 55 55 FC)
    # golf mk5 r32 (7.1.1)  (0C F0 BF FC 30 03 F3 FE AA FA 55 55 FC)

    # first strat (7.1), locate GGHFM (14x14 of ones (0x80)) (near KFKHFM) and walk back with a sliding window from there on
    gghfm_sig = Pattern([0x80] * 14 * 14, ''.join(['x'] * 14 * 14))
    gghfm_pattern = gghfm_sig.scan(me7.disasm.orig_bin)
    if len(gghfm_pattern) > 0:
        for ggfhfm_offset in gghfm_pattern:

            # pattern1, looks after the eskonf
            eskonf = Pattern(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0x02, 0x02, 0x02, 0x00], 
                "?????????????xxxxx"
            ).scan_reverse(me7.disasm.orig_bin[ggfhfm_offset-256:ggfhfm_offset])
            if len(eskonf) > 0:
                eskonf_offset = ggfhfm_offset-256+eskonf[0]
                found_eskonf["version"] = "me7.1"
                found_eskonf["file_offset"] = eskonf_offset
                found_eskonf["bytes"] = me7.disasm.orig_bin[eskonf_offset:eskonf_offset+13]
                me7.eskonf = found_eskonf
                return True

            # pattern2, should be good for up to 6 cyls
            eskonf = Pattern(
                [0, 0, 0, 0, 0, 0, 0xF3, 0, 0, 0, 0x55, 0x55, 0], 
                "??????x???xx?"
            ).scan_reverse(me7.disasm.orig_bin[ggfhfm_offset-256:ggfhfm_offset])
            if len(eskonf) > 0:
                eskonf_offset = ggfhfm_offset-256+eskonf[0]
                found_eskonf["version"] = "me7.1"
                found_eskonf["file_offset"] = eskonf_offset
                found_eskonf["bytes"] = me7.disasm.orig_bin[eskonf_offset:eskonf_offset+13]
                me7.eskonf = found_eskonf
                return True


    # second strat (7.1.1), locate ESKONF_AGR ja ESKONF_NL and walk back with a sliding window from there on
    eskonf_agr_nl = Pattern([0xAA] * 13 * 3, ''.join(['x'] * 13 * 3))
    eskonf_agr_nl_pattern = eskonf_agr_nl.scan_reverse(me7.disasm.orig_bin)
    if len(eskonf_agr_nl_pattern) > 0:
        for eskonf_agr_nl_offset in eskonf_agr_nl_pattern:
            eskonf = Pattern(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0x02, 0x02, 0x02, 0x00], 
                "?????????????xxxxx"
            ).scan_reverse(me7.disasm.orig_bin[eskonf_agr_nl_offset-256:eskonf_agr_nl_offset])
            if len(eskonf) > 0:
                eskonf_offset = eskonf_agr_nl_offset-256+eskonf[0]
                found_eskonf["version"] = "me7.1.1"
                found_eskonf["file_offset"] = eskonf_offset
                found_eskonf["bytes"] = me7.disasm.orig_bin[eskonf_offset:eskonf_offset+13]                  
                me7.eskonf = found_eskonf
                return True


    # third stat (7.5) use heuristics of the me7.5 eskonf
    # TODO implement from me7eskonf C source


    return False