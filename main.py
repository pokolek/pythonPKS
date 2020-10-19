from scapy.all import *


class Ramec:
    cislo_ramca = []
    dst_mac = []
    src_mac = []
    dlzka_pcap = 0
    dlzka_medium = 0
    typ_ramca_or_dlzka = ""
    ethernetII = False
    dsap_ssap = ""
    src_ip = []
    dst_ip = []
    vnoreny_protokol = ""
    pole_bytov = bytearray()

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
        tmp_ramec = Ramec(cislo_ramca)
        f.write(50 * "-")
        f.write("\n")
        f.write(tmp_ramec.cislo_ramca.__str__() + ". ramec\n")

        tmp_ramec.pole_bytov = bytes(ramec)

        for bajt in tmp_ramec.pole_bytov:  # prechadzame ramec po bytoch
            tmp_ramec.dlzka_pcap += 1
            if tmp_ramec.dlzka_pcap <= 6:  # DST MAC
                tmp_ramec.dst_mac.append(bajt)

            elif 6 < tmp_ramec.dlzka_pcap <= 12:  # SRC MAC
                tmp_ramec.src_mac.append(bajt)

            elif 12 < tmp_ramec.dlzka_pcap < 14:  # Type/Lenght
                tmp_ramec.typ_ramca_or_dlzka += ('%02x' % bajt).__str__()

            elif tmp_ramec.dlzka_pcap == 14:  # zistujeme ci to je ether
                tmp_ramec.typ_ramca_or_dlzka += ('%02x' % bajt).__str__()
                if int(tmp_ramec.typ_ramca_or_dlzka, 16) > 1536:
                    tmp_ramec.ethernetII = True

            elif 14 < tmp_ramec.dlzka_pcap <= 16 and not tmp_ramec.ethernetII:  # zistujeme 802.3
                tmp_ramec.dsap_ssap += ('%02x' % bajt).__str__()

        if tmp_ramec.dlzka_pcap + 4 < 64:
            tmp_ramec.dlzka_medium = 64
        else:
            tmp_ramec.dlzka_medium = tmp_ramec.dlzka_pcap + 4

        f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_pcap.__str__() + " B\n")
        f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_medium.__str__() + " B\n")

        if tmp_ramec.ethernetII:
            f.write("Ethernet II\n")
        else:
            if tmp_ramec.dsap_ssap.__str__() == "ffff":
                f.write("802.3 - RAW\n")
            elif tmp_ramec.dsap_ssap.__str__() == "aaaa":
                f.write("802.3 - LLC + SNAP\n")
            else:
                f.write("802.3 - LLC\n")

        f.write("zdrojova MAC adresa: ")
        for i in range(6):
            f.write('%02x ' % tmp_ramec.src_mac[i])

        f.write("\ncielova MAC adresa: ")
        for i in range(6):
            f.write('%02x ' % tmp_ramec.dst_mac[i])

        f.write("\n")

        vypis_ramca = 0
        for bajt in tmp_ramec.pole_bytov:
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
        list_ramcov.append(tmp_ramec)


def analyzuj_ramec_2(subor_ramcov):  # funkcia ktora analyzuje ramec podla bodu 2
    cislo_ramca = 0

    f.write("Analyza podla bodu 2\nNazov analyzovaneho suboru: " + nazov_suboru + "\n")
    for ramec in subor_ramcov:
        cislo_ramca += 1
        tmp_ramec = Ramec(cislo_ramca)
        f.write(50 * "-")
        f.write("\n")
        f.write(tmp_ramec.cislo_ramca.__str__() + ". ramec\n")

        tmp_ramec.pole_bytov = bytes(ramec)

        for bajt in tmp_ramec.pole_bytov:  # prechadzame ramec po bytoch
            tmp_ramec.dlzka_pcap += 1
            if tmp_ramec.dlzka_pcap <= 6:  # DST MAC
                tmp_ramec.dst_mac.append(bajt)

            elif 6 < tmp_ramec.dlzka_pcap <= 12:  # SRC MAC
                tmp_ramec.src_mac.append(bajt)

            elif 12 < tmp_ramec.dlzka_pcap < 14:  # Type/Lenght
                tmp_ramec.typ_ramca_or_dlzka += ('%02x' % bajt).__str__()

            elif tmp_ramec.dlzka_pcap == 14:  # zistujeme ci to je ether
                tmp_ramec.typ_ramca_or_dlzka += ('%02x' % bajt).__str__()
                if int(tmp_ramec.typ_ramca_or_dlzka, 16) > 1536:
                    tmp_ramec.ethernetII = True

            elif 14 < tmp_ramec.dlzka_pcap <= 16 and not tmp_ramec.ethernetII:  # zistujeme 802.3
                tmp_ramec.dsap_ssap += ('%02x' % bajt).__str__()

        if tmp_ramec.dlzka_pcap + 4 < 64:
            tmp_ramec.dlzka_medium = 64
        else:
            tmp_ramec.dlzka_medium = tmp_ramec.dlzka_pcap + 4

        f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_pcap.__str__() + " B\n")
        f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_medium.__str__() + " B\n")

        if tmp_ramec.ethernetII:
            f.write("Ethernet II\n")
            if ether_typy.get(int(tmp_ramec.typ_ramca_or_dlzka, 16)):
                f.write("Vnoreny protokol: " + ether_typy.get(int(tmp_ramec.typ_ramca_or_dlzka, 16)) + "\n")
        else:
            if tmp_ramec.dsap_ssap.__str__() == "ffff":
                f.write("802.3 - RAW\n")
            elif tmp_ramec.dsap_ssap.__str__() == "aaaa":
                f.write("802.3 - LLC + SNAP\n")
            else:
                f.write("802.3 - LLC\n")

        f.write("zdrojova MAC adresa: ")
        for i in range(6):
            f.write('%02x ' % tmp_ramec.src_mac[i])

        f.write("\ncielova MAC adresa: ")
        for i in range(6):
            f.write('%02x ' % tmp_ramec.dst_mac[i])

        f.write("\n")

        vypis_ramca = 0
        for bajt in tmp_ramec.pole_bytov:
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
        list_ramcov.append(tmp_ramec)


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
        print("Analyzovanych bolo " + len(list_ramcov).__str__() + " ramcov...")

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
