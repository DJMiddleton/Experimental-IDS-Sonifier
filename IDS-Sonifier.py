import struct
import textwrap
import socket
import time
import os


def main():
    packet_count = 0
    pd_start = '6;'
    null_flood = 0
    syn_flood = 0
    fin_flood = 0
    attack_type = '0;'
    n_minutes = 0
    s_minutes = 0
    f_minutes = 0

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Initialise pure data
    os.system("echo '" + pd_start + "' | pdsend 4545 localhost")

    while True:
        packet_count += 1
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = frame(raw_data)
        print('\n---------------------------------------------------------------------------------------')
        print('packet count: {}'.format(packet_count))
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}\n'.format(dest_mac, src_mac, eth_proto))

        # checking protocol for standard traffic
        if eth_proto == 8:
            (version, header, ttl, proto, src, target, data) = ipv4(data)
            print('IPv4 Packet:')
            print('Version: {:>2}, Header Length: {}, TTL: {}'.format(version, header, ttl))
            print('Protocol: {}, Source: {}, Target: {}\n'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp(data)
                print('ICMP Packet:')
                print('Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print('Data: {}'.format(data))

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data = tcp(data)
                print('TCP Segment:')
                print('Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print('Sequence: {}, Acknowledgment: {}\n'.format(sequence, acknowledgment))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}\n'.format(urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag))

                # calculating packet type
                pack_type = 0
                if urg_flag == 1:
                    pack_type += 1
                if ack_flag == 1:
                    pack_type += 23
                if psh_flag == 1:
                    pack_type += 82
                if rst_flag == 1:
                    pack_type += 133
                if syn_flag == 1:
                    pack_type += 304
                if fin_flag == 1:
                    pack_type += 580

                # checking for network attacks
                if pack_type == 884:
                    print('Danger: scan warning!')
                    attack_type = '1;'

                if pack_type == 663:
                    print('Danger: XMAS tree!')
                    attack_type = '2;'

                if pack_type == 0:
                    null_flood += 1
                    # checking if 100 of same packet type are received within 1 minute
                    if null_flood == 1:
                        n_timer = time.gmtime()
                        n_minutes = n_timer[4]
                    if null_flood == 100:
                        n_flood_timer = time.gmtime()
                        n_elapsed = n_flood_timer[4]
                        if n_minutes == n_elapsed:
                            null_flood = 0
                            print('Danger: Null flood!')
                            attack_type = '3;'

                if pack_type == 304:
                    syn_flood += 1
                    # checking if 100 of same packet type are received within 1 minute
                    if syn_flood == 1:
                        s_timer = time.gmtime()
                        s_minutes = s_timer[4]
                    if syn_flood == 100:
                        s_flood_timer = time.gmtime()
                        s_elapsed = s_flood_timer[4]
                        if s_minutes == s_elapsed:
                            syn_flood = 0
                            print('Danger: Syn flood!')
                            attack_type = '4;'

                if pack_type == 580:
                    fin_flood += 1
                    # checking if 100 of same packet type are received within 1 minute
                    if fin_flood == 1:
                        f_timer = time.gmtime()
                        f_minutes = f_timer[4]
                    if fin_flood == 100:
                        f_flood_timer = time.gmtime()
                        f_elapsed = f_flood_timer[4]
                        if f_minutes == f_elapsed:
                            fin_flood = 0
                            print('Danger: Fin flood!')
                            attack_type = '5;'

                if attack_type == '0;':
                    print('network stable')
                else:
                    # send attack type to pure data
                    os.system("echo '" + attack_type + "' | pdsend 4545 localhost")


# unpack frame
def frame(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return \
        mac(dest_mac), mac(src_mac), socket.htons(eth_proto), data[14:]


# format mac address
def mac(addr_bytes):
    str_bytes = map('{:02x}'.format, addr_bytes)
    mac_addr = ':'.join(str_bytes).upper()
    return \
        mac_addr


# unpack IPv4
def ipv4(data):
    header_length = data[0]
    version = header_length >> 4
    header = (header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return \
        version, header, ttl, proto, ipv4_addr(src), ipv4_addr(dest), data[header:]


# returns properly formatted ipv4 address
def ipv4_addr(addr):
    return \
        '.'.join(map(str, addr))


# unpacks ICMP packet
def icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return \
        icmp_type, code, checksum, data[4:]


# unpacks TCP packet
def tcp(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    urg_flag = (offset_reserved_flags & 32) >> 5
    ack_flag = (offset_reserved_flags & 16) >> 4
    psh_flag = (offset_reserved_flags & 8) >> 3
    rst_flag = (offset_reserved_flags & 4) >> 2
    syn_flag = (offset_reserved_flags & 2) >> 1
    fin_flag = offset_reserved_flags & 1
    return \
        src_port, dest_port, sequence, acknowledgement, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data[offset:]


main()