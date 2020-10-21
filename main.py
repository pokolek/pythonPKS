from scapy.all import *


class Ramec:

    def __init__(self, cislo_ramca):
        self.cislo_ramca = cislo_ramca
        self.dst_mac = []
        self.src_mac = []
        self.dlzka_pcap = 0
        self.dlzka_medium = 0
        self.typ_ramca_or_dlzka = ""
        self.ethernetII_flag = False
        self.ip_flag = False
        self.tcp_flag = False
        self.udp_flag = False
        self.src_port = ""
        self.dst_port = ""
        self.dsap = ""
        self.ssap = ""
        self.vnoreny_protokol = ""
        self.ip_protokol = ""
        self.src_ip = []
        self.dst_ip = []
        self.pole_bytov = bytearray()


def inicializuj_konfiguracny_subor(ether_typy, llc_sap_typy, ip_protokoly, tcp_porty, udp_porty):
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

                    elif typ_zoznamu == "#llc_sap_typy":
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
                    tmp_ramec.ethernetII_flag = True

            elif 14 < tmp_ramec.dlzka_pcap <= 15 and not tmp_ramec.ethernetII_flag:  # zistujeme 802.3
                tmp_ramec.dsap += ('%02x' % bajt).__str__()

            elif 15 < tmp_ramec.dlzka_pcap <= 16 and not tmp_ramec.ethernetII_flag:  # zistujeme 802.3
                tmp_ramec.ssap += ('%02x' % bajt).__str__()

        if tmp_ramec.dlzka_pcap + 4 < 64:
            tmp_ramec.dlzka_medium = 64
        else:
            tmp_ramec.dlzka_medium = tmp_ramec.dlzka_pcap + 4

        f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_pcap.__str__() + " B\n")
        f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_medium.__str__() + " B\n")

        if tmp_ramec.ethernetII_flag:
            f.write("Ethernet II\n")
        else:
            if tmp_ramec.dsap.__str__() == "ff":
                f.write("802.3 - RAW\n")
            elif tmp_ramec.dsap.__str__() == "aa":
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
        del tmp_ramec


def analyzuj_ramec_2(subor_ramcov, list_ramcov):  # funkcia ktora analyzuje ramec podla bodu 2
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
                    tmp_ramec.ethernetII_flag = True

            elif 14 < tmp_ramec.dlzka_pcap <= 15 and not tmp_ramec.ethernetII_flag:  # zistujeme 802.3 dsap
                tmp_ramec.dsap += ('%02x' % bajt).__str__()

            elif 15 < tmp_ramec.dlzka_pcap <= 16 and not tmp_ramec.ethernetII_flag:  # zistujeme 802.3 ssap
                tmp_ramec.ssap += ('%02x' % bajt).__str__()

        if tmp_ramec.dlzka_pcap + 4 < 64:
            tmp_ramec.dlzka_medium = 64
        else:
            tmp_ramec.dlzka_medium = tmp_ramec.dlzka_pcap + 4

        f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_pcap.__str__() + " B\n")
        f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_medium.__str__() + " B\n")

        if tmp_ramec.ethernetII_flag:
            f.write("Ethernet II\n")
            if ether_typy.get(int(tmp_ramec.typ_ramca_or_dlzka, 16)):
                f.write("Vnoreny protokol: " + ether_typy.get(int(tmp_ramec.typ_ramca_or_dlzka, 16)) + "\n")
        else:
            if tmp_ramec.dsap.__str__() == "ff":
                f.write("802.3 - RAW\n")
                f.write("Vnoreny protokol: IPX\n")
            elif tmp_ramec.dsap.__str__() == "aa":
                f.write("802.3 - LLC + SNAP\n")
                f.write("Vnoreny protokol: SNAP\n")
            else:
                f.write("802.3 - LLC\n")
                if lsap_typy.get(int(tmp_ramec.dsap, 16)):
                    f.write("Vnoreny protokol: " + lsap_typy.get(int(tmp_ramec.dsap, 16)) + "\n")

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


def analyzuj_ramec_3(subor_ramcov, list_ramcov):  # funkcia ktora analyzuje ramec podla bodu 2
    cislo_ramca = 0
    dst_ip_adresy = {}

    f.write("Analyza podla bodu 3\nNazov analyzovaneho suboru: " + nazov_suboru + "\n")
    for ramec in subor_ramcov:
        cislo_ramca += 1
        tmp_ramec = Ramec(cislo_ramca)
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
                    tmp_ramec.ethernetII_flag = True
                    if ether_typy.get(int(tmp_ramec.typ_ramca_or_dlzka, 16)) == "IPv4":
                        tmp_ramec.ip_flag = True


            elif tmp_ramec.dlzka_pcap == 24 and tmp_ramec.ip_flag:  #hladame protokol ip
                tmp_ramec.ip_protokol = ip_protokoly.get(bajt)
                if tmp_ramec.ip_protokol == "TCP":
                    tmp_ramec.tcp_flag = True
                elif tmp_ramec.ip_protokol == "UDP":
                    tmp_ramec.udp_flag = True


            elif 27 <= tmp_ramec.dlzka_pcap <= 30 and tmp_ramec.ip_flag:
                tmp_ramec.src_ip.append(bajt)

            elif 31 <= tmp_ramec.dlzka_pcap <= 34 and tmp_ramec.ip_flag:
                tmp_ramec.dst_ip.append(bajt)

            elif 34 < tmp_ramec.dlzka_pcap <= 36 and tmp_ramec.ip_flag:
                tmp_ramec.src_port += ('%02x' % bajt).__str__()

            elif 36 < tmp_ramec.dlzka_pcap <= 38 and tmp_ramec.ip_flag:
                tmp_ramec.dst_port += ('%02x' % bajt).__str__()

        if tmp_ramec.ip_flag:
            dst_ip_adresy[tmp_ramec.dst_ip.__str__()] = 0

        if tmp_ramec.dlzka_pcap + 4 < 64:
            tmp_ramec.dlzka_medium = 64
        else:
            tmp_ramec.dlzka_medium = tmp_ramec.dlzka_pcap + 4


        if tmp_ramec.ethernetII_flag and tmp_ramec.ip_flag:
            f.write(50 * "-")
            f.write("\n")
            f.write(tmp_ramec.cislo_ramca.__str__() + ". ramec\n")
            f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_pcap.__str__() + " B\n")
            f.write("dlzka ramca poskytnuta pcap API: " + tmp_ramec.dlzka_medium.__str__() + " B\n")
            f.write("Ethernet II\n")

            f.write("zdrojova MAC adresa: ")
            for i in range(6):
                f.write('%02x ' % tmp_ramec.src_mac[i])

            f.write("\ncielova MAC adresa: ")
            for i in range(6):
                f.write('%02x ' % tmp_ramec.dst_mac[i])

            if ether_typy.get(int(tmp_ramec.typ_ramca_or_dlzka, 16)):
                f.write("\nVnoreny protokol: " + ether_typy.get(int(tmp_ramec.typ_ramca_or_dlzka, 16)))

            f.write("\nzdrojova IP adresa: ")
            for i in range(3):
                f.write('%d.' % tmp_ramec.src_ip[i])
            f.write('%d' % tmp_ramec.src_ip[3])

            f.write("\ncielova IP adresa: ")
            for i in range(3):
                f.write('%d.' % tmp_ramec.dst_ip[i])
            f.write('%d' % tmp_ramec.dst_ip[3])

            f.write("\n" + tmp_ramec.ip_protokol)

            if tmp_ramec.tcp_flag:
                if tcp_porty.get(int(tmp_ramec.dst_port, 16)):
                    f.write("\n" + tcp_porty.get(int(tmp_ramec.dst_port, 16)))

                elif tcp_porty.get(int(tmp_ramec.src_port, 16)):
                    f.write("\n" + tcp_porty.get(int(tmp_ramec.src_port, 16)))

            elif tmp_ramec.udp_flag:
                if udp_porty.get(int(tmp_ramec.dst_port, 16)):
                    f.write("\n" + udp_porty.get(int(tmp_ramec.dst_port, 16)))

                elif udp_porty.get(int(tmp_ramec.src_port, 16)):
                    f.write("\n" + udp_porty.get(int(tmp_ramec.src_port, 16)))

            f.write("\nzdrojovy port: " + int(tmp_ramec.src_port, 16).__str__())
            f.write("\ncielovy port: " + int(tmp_ramec.dst_port, 16).__str__() + "\n")


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
        else:
            list_ramcov.append(tmp_ramec)
            continue

    pocet_adries = -1
    max_adresa = []

    for ramec in list_ramcov:
        if ramec.ip_flag:
            dst_ip_adresy[ramec.dst_ip.__str__()] += 1

    for adresa in dst_ip_adresy:
        f.write("\n")
        if pocet_adries < dst_ip_adresy[adresa]:
            pocet_adries = dst_ip_adresy[adresa]
            max_adresa = adresa

        adresa = adresa.replace('[', '')
        adresa = adresa.replace(']', '')
        adresa = adresa.replace(', ', '.')

        f.write(adresa)

    max_adresa = max_adresa.replace('[', '')
    max_adresa = max_adresa.replace(']', '')
    max_adresa = max_adresa.replace(', ', '.')

    f.write("\nAdresa uzla s najvacsim poctom odoslanych paketov: " + max_adresa.__str__() + " = " + pocet_adries.__str__() + " paketov\n")
    del tmp_ramec



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
        analyzuj_ramec_2(subor_ramcov, list_ramcov)
        print("Bola vykonana analyza suboru " + nazov_suboru + " podla bodu 2, pozri subor...")
        print("Analyzovanych bolo " + len(list_ramcov).__str__() + " ramcov...")

    elif int(cislo_vykonania) == 3:
        analyzuj_ramec_3(subor_ramcov, list_ramcov)
        print("Bola vykonana analyza suboru " + nazov_suboru + " podla bodu 3, pozri subor...")
        print("Analyzovanych bolo " + len(list_ramcov).__str__() + " ramcov...")

    elif int(cislo_vykonania) == 4:
        print("zad4")
    else:
        print("Zadal si nespravne cislo skus to znova...")
        continue
    f.close()
    break
