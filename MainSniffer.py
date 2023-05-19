import socket       
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
	connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #creating socket
    
	while True: 
		raw_data, addr = connection.recvfrom(65536) #storeincoming data and set buffer size
		dest_mac, src_mac, ethernet_protocol, data = ethernet_frame(raw_data)
		print('\nEthernet Frame: ')
		print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, ethernet_protocol))
		
		# protocol 8 for IPv4
		if ethernet_protocol == 8:
			(version, header_length, ttl, protocol, src, target, data) = ipv4_packet(data)
			print(TAB_1 + 'IPv4 Packet:')
			print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
			print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(protocol, src, target))
			
			#ICMP
			if protocol == 1:
				icmp_type, code, checksum, data = icmp_packet(data)
				print(TAB_1 + 'ICMP Packet:')
				print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
				print(TAB_2 + 'Data:')
				print(format_multi_line(DATA_TAB_3, data))
			
			#TCP
			elif protocol == 6:
				src_port, dst_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_packet(data)
				print(TAB_1 + 'TCP Packet:')
				print(TAB_2 + 'Source Port: {}, Dest Port: {}'.format(src_port, dst_port))
				print(TAB_2 + 'sequence: {}, ack: {}'.format(sequence, ack))
				print(TAB_2 + 'Flags:')
				print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
				print(TAB_2 + 'Data:')
				print(format_multi_line(DATA_TAB_3, data))
				
			#UDP
			elif protocol == 17:
				src_port, dst_port, length, data = udp_packet(data)
				print(TAB_1 + 'UDP Packet:')
				print(TAB_2 + 'Source Port: {}, Dest Port: {}, Length: {}'.format(src_port, dst_port, length))
			else: 
				print(TAB_1 + 'Data:')
				print(format_multi_line(DATA_TAB_2, data))
		else: 
			print('Data:')
			print(format_multi_line(DATA_TAB_1, data))

#ethernet frame unpacking
def ethernet_frame(data):
	dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14]) # unpacks 14Bytes from ethernet data
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(protocol), data[14:]

#formatting MAC Address
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr) #formats MAC Ex. AA:BB:CC:DD:EE:FF
	mac_addr = ':'.join(bytes_str).upper() 
	return mac_addr

#Unpacks IPv4 packet
def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4 # shift to get version bits
	header_length = (version_header_length & 15) * 4 # get bits for header length
	ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, protocol, ipv4(src), ipv4(target), data[header_length:]

#formats IPv4 address
def ipv4(addr):
	return '.'.join(map(str, addr))

#unpack ICMP packets
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]

# unpack TCP Packets
def tcp_packet(data):
	(src_port, dst_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	return src_port, dst_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_packet(data):
	src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dst_port, size, data[8:]
	
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()







