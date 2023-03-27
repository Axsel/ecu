import sys
import os

from me7.me7flash import Me7Flash


def test(fpath):
    print(fpath)
    f = open(fpath, "rb")
    hexdata = f.read()
    f.close()

    flash = Me7Flash(hexdata)
    
    flash.find_vars()
    flash.find_maps()


def main():
    # A3
    #test("flashes/022906032CB 5604_mpps_ori.Bin")
 
    # golf hall
    test("flashes/022906032E-0008.bin")
 
    # vr6 2.8 golf
    #test("flashes/022906032BG-0004.bin")
 
    # phaeton vr6
    #test("flashes/0261207688 1037367668 022906032BN VW Phaeton 3.2l Bosch ME7.1.1.original.bin")
 
    # audi a4 2.4l v6
    #test("flashes/Audi A4 2.4L V6 30V 2002 125KW 0261208038 8E0909552M 366138 402A original")

    # ibiza 1.8t me7.5
    #test("flashes/1.8t_ibiza_fr_mpps_read_flash.bin")

    return

if __name__ == "__main__":
    main()