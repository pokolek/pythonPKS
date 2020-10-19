from scapy.all import *

class Ramec:
    cislo_ramca = []
    dst_mac = []
    src_mac = []
    dlzka_pcap = 0
    dlzka_medium = 0
    typ_ramca = ""
    dlzka_z_ramca = ""
    ethernetII = False
    dsap = ""
    ssap = ""
    src_ip = []
    dst_ip = []
    vnoreny_protokol = ""
    ramec_v_bytoch = bytearray()

    def __init__(self, cislo_ramca):
        self.cislo_ramca = cislo_ramca





def inicializuj_konfiguracny_subor(ether_typy, lsap_typy, ip_protokoly, tcp_porty, udp_porty):
    with open("konfiguracny_subor.txt", "r") as file:
        typ_zoznamu = ""
        predchadzajuci = ""
        dalsi = ""
        flag = 0
        for line in file:
            for word in line.split():
                if word[0] == "#":
                    typ_zoznamu = word
                    continue

                # urcenie predchadzajuceho a nasledujuceho slova pre nahratie do slovnika
                if typ_zoznamu and not flag:
                    predchadzajuci = word
                    flag = 1
                    continue
                elif typ_zoznamu and flag:
                    dalsi = word
                    flag = 0

                # konfiguracia do jednotlivych slovnikov
                if predchadzajuci:
                    if typ_zoznamu == "#ether_typy":
                        ether_typy[int(predchadzajuci, 0)] = dalsi

                    elif typ_zoznamu == "#lsap_typy":
                        lsap_typy[int(predchadzajuci, 0)] = dalsi

                    elif typ_zoznamu == "#ip_protokoly":
                        ip_protokoly[int(predchadzajuci, 0)] = dalsi

                    elif typ_zoznamu == "#tcp_porty":
                        tcp_porty[int(predchadzajuci, 0)] = dalsi

                    elif typ_zoznamu == "#udp_porty":
                        udp_porty[int(predchadzajuci, 0)] = dalsi


def analyzuj_ramec_1(subor_ramcov, list_ramcov):  # funkcia ktora analyzuje ramec podla bodu 1
    cislo_ramca = 0
    f.write("Analyza podla bodu 1\nNazov analyzovaneho suboru: " + nazov_suboru + "\n")
    for ramec in subor_ramcov:
        cislo_ramca += 1
        f.write(50 * "-")
        f.write("\n")
        f.write(cislo_ramca.__str__() + ". ramec\n")
        pole_bytov = bytes(ramec)

        dst_mac = []
        src_mac = []
        dlzka_pcap = 0
        dlzka_medium = 0
        typ_ramca_or_dlzka = ""
        ethernetII = False
        dsap_ssap = ""

        for bajt in pole_bytov:  # prechadzame ramec po bytoch
            dlzka_pcap += 1
            if dlzka_pcap <= 6:  # DST MAC
                dst_mac.append(bajt)
            elif 6 < dlzka_pcap <= 12:  # SRC MAC
                src_mac.append(bajt)
            elif 12 < dlzka_pcap < 14:  # Type/Lenght
                typ_ramca_or_dlzka += ('%02x' % bajt).__str__()
            elif dlzka_pcap == 14:  # zistujeme ci to je ether
                typ_ramca_or_dlzka += ('%02x' % bajt).__str__()
                if int(typ_ramca_or_dlzka, 16) > 1536:
                    ethernetII = True
            elif 14 < dlzka_pcap <= 16 and ethernetII == False:  # zistujeme 802.3
                dsap_ssap += ('%02x' % bajt).__str__()

        if dlzka_pcap + 4 < 64:
            dlzka_medium = 64
        else:
            dlzka_medium = dlzka_pcap + 4

        f.write("dlzka ramca poskytnuta pcap API: " + dlzka_pcap.__str__() + " B\n")
        f.write("dlzka ramca poskytnuta pcap API: " + dlzka_medium.__str__() + " B\n")

        if ethernetII == True:
            f.write("Ethernet II\n")
        else:
            if dsap_ssap.__str__() == "ffff":
                f.write("802.3 - RAW\n")
            elif dsap_ssap.__str__() == "aaaa":
                f.write("802.3 - LLC + SNAP\n")
            else:
                f.write("802.3 - LLC\n")

        f.write("zdrojova MAC adresa: ")
        for i in range(6):
            f.write('%02x ' % src_mac[i])

        f.write("\ncielova MAC adresa: ")
        for i in range(6):
            f.write('%02x ' % dst_mac[i])

        f.write("\n")

        vypis_ramca = 0
        for bajt in pole_bytov:
            vypis_ramca += 1
            f.write('%02x ' % bajt)
            if vypis_ramca == 8:
                f.write(" ")
            if vypis_ramca == 16:
                vypis_ramca = 0
                f.write("\n")

        f.write("\n")

        f.write(50 * "-")
        f.write("\n")



def analyzuj_ramec_2(subor_ramcov):  # funkcia ktora analyzuje ramec podla bodu 2
    cislo_ramca = 0
    f.write("Analyza podla bodu 1\nNazov analyzovaneho suboru: " + nazov_suboru + "\n")
    for ramec in subor_ramcov:
        cislo_ramca += 1
        f.write(50 * "-")
        f.write("\n")
        f.write(cislo_ramca.__str__() + ". ramec\n")
        pole_bytov = bytes(ramec)

        dst_mac = []
        src_mac = []
        dlzka_pcap = 0
        dlzka_medium = 0
        typ_ramca_or_dlzka = ""
        ethernetII = False
        dsap_ssap = ""

        for bajt in pole_bytov:  # prechadzame ramec po bytoch
            dlzka_pcap += 1
            if dlzka_pcap <= 6:  # DST MAC
                dst_mac.append(bajt)
            elif 6 < dlzka_pcap <= 12:  # SRC MAC
                src_mac.append(bajt)
            elif 12 < dlzka_pcap < 14:  # Type/Lenght
                typ_ramca_or_dlzka += ('%02x' % bajt).__str__()
            elif dlzka_pcap == 14:  # zistujeme ci to je ether
                typ_ramca_or_dlzka += ('%02x' % bajt).__str__()
                if int(typ_ramca_or_dlzka, 16) > 1536:
                    ethernetII = True
            elif 14 < dlzka_pcap <= 16 and ethernetII == False:  # zistujeme 802.3
                dsap_ssap += ('%02x' % bajt).__str__()

        if dlzka_pcap + 4 < 64:
            dlzka_medium = 64
        else:
            dlzka_medium = dlzka_pcap + 4

        f.write("dlzka ramca poskytnuta pcap API: " + dlzka_pcap.__str__() + " B\n")
        f.write("dlzka ramca poskytnuta pcap API: " + dlzka_medium.__str__() + " B\n")

        if ethernetII == True:
            f.write("Ethernet II\n")
            if(ether_typy.get(int(typ_ramca_or_dlzka, 16))):
                f.write("Vnoreny protokol: " + ether_typy.get(int(typ_ramca_or_dlzka, 16)) + "\n")
        else:
            if dsap_ssap.__str__() == "ffff":
                f.write("802.3 - RAW\n")
            elif dsap_ssap.__str__() == "aaaa":
                f.write("802.3 - LLC + SNAP\n")
            else:
                f.write("802.3 - LLC\n")

        f.write("zdrojova MAC adresa: ")
        for i in range(6):
            f.write('%02x ' % src_mac[i])

        f.write("\ncielova MAC adresa: ")
        for i in range(6):
            f.write('%02x ' % dst_mac[i])

        f.write("\n")

        vypis_ramca = 0
        for bajt in pole_bytov:
            vypis_ramca += 1
            f.write('%02x ' % bajt)
            if vypis_ramca == 8:
                f.write(" ")
            if vypis_ramca == 16:
                vypis_ramca = 0
                f.write("\n")

        f.write("\n")

        f.write(50 * "-")
        f.write("\n")

def analyzuj_ramec_3(ramec_vbytoch):  # funkcia ktora analyzuje ramec podla bodu 2
    print(ether_typy)

ether_typy = {}
lsap_typy = {}
ip_protokoly = {}
tcp_porty = {}
udp_porty = {}

inicializuj_konfiguracny_subor(ether_typy, lsap_typy, ip_protokoly, tcp_porty, udp_porty)

list_ramcov = []

print(ether_typy)
print(lsap_typy)
print(ip_protokoly)
print(tcp_porty)
print(udp_porty)

f = open("analyza.txt", "w")

while True:
    try:
        nazov_suboru = input("Zadaj nazov suboru ktory chces analyzovat: ")
        subor_ramcov = rdpcap('./frames/' + nazov_suboru)
        print(subor_ramcov)
    except FileNotFoundError:
        print("Subor sa nenasiel, zadaj nazov este raz...")
        continue
    else:
        print("Subor sa nasiel...")
        break

while True:
    cislo_vykonania = input("Zadaj cislo bodu zadania ktore chces vykonat: ")

    if int(cislo_vykonania) == 1:
        analyzuj_ramec_1(subor_ramcov, list_ramcov)
        print("Bola vykonana analyza suboru " + nazov_suboru + " podla bodu 1, pozri subor...")

    elif int(cislo_vykonania) == 2:
        analyzuj_ramec_2(subor_ramcov)
        print("Bola vykonana analyza suboru " + nazov_suboru + " podla bodu 2, pozri subor...")
    elif int(cislo_vykonania) == 3:
        print()
    elif int(cislo_vykonania) == 4:
        print("zad4")
    else:
        print("Zadal si nespravne cislo skus to znova...")
        continue
    f.close()
    break
