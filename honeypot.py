from scapy.all import IP, TCP, Ether, Raw, ARP, UDP, ICMP, sendp, rdpcap, srp, NBTSession, SMB_Header
from netfilterqueue import NetfilterQueue
from datetime import datetime, timezone
from random import randint
from copy import deepcopy
from joblib import load
import pandas as pd
import threading
import json
import time
import os

with open('config.json', 'r') as file:
		config = json.load(file)

protocols = config['protocols']
op_sys = config['os']
my_mac = config['honey_mac']

tcp_model = load("resulted_models/tcp_model.joblib")
http_model = None
rdp_model = None
smb_model = None

for protocol in protocols:
	if protocol == 'http':
		http_model = load("resulted_models/http_model.joblib")
	elif protocol == 'rdp':
		rdp_model = load("resulted_models/rdp_model.joblib")
	elif protocol == 'smb':
		smb_model = load("resulted_models/smb_model.joblib")

reply_packets = {}
arp_table = {}

just_sent_http_response = False

ttl = 0
ip_id = randint(10000, 40000)
ip_id_lock = threading.Lock()

TS_Base = 0
TS_Granularity = 0
TS_Start = 0
TS_Current = 0

class TCPStream:
	tcp_streams = {}
	tcp_streams_lock = threading.Lock()

	def __init__(self, packet, last_timestamp):
		self.packet = packet 
		src_ip = packet[IP].src
		src_port = packet[TCP].sport
		dst_ip = packet[IP].dst
		dst_port = packet[TCP].dport
		self.key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
		self.time_to_retry = 1
		self.remaining_retries = [2, 4, 8, 8]
		self.last_timestamp = last_timestamp

	def __str__(self):
		return f"{self.key}"
	
	def add_stream(self):
		# daca exista se suprascrie, daca nu, se adauga
		with TCPStream.tcp_streams_lock:
			TCPStream.tcp_streams[self.key] = self

	def decrease_timestamp(self):
		global ip_id
		current_tiemstamp = time.perf_counter()
		time_elapsed = current_tiemstamp - self.last_timestamp
		self.time_to_retry -= time_elapsed
		self.last_timestamp = current_tiemstamp

		if self.time_to_retry <= 0:
			if len(self.remaining_retries) == 0:
				# Modific pachetul pnetru a deveni un RST
				self.packet[TCP].flags = 'R'
				self.packet[TCP].seq += 1
				self.packet[TCP].window = 0
				del self.packet[TCP].options
				del self.packet[IP].len
				del self.packet[TCP].dataofs
				del self.packet[IP].chksum
				del self.packet[TCP].chksum

				with ip_id_lock:
					self.packet[IP].id = ip_id
					ip_id += 1
					if ip_id > 65535:
						ip_id = 0
				sendp(self.packet)
				with TCPStream.tcp_streams_lock:
					del TCPStream.tcp_streams[self.key]
			else:
				# Retransmiterea pachetului
				remaining = -self.time_to_retry if self.time_to_retry < 0 else 0
				self.time_to_retry = self.remaining_retries[0]
				self.time_to_retry -= remaining
				self.remaining_retries.pop(0)
				with ip_id_lock:
					self.packet[IP].id = ip_id
					ip_id += 1
					if ip_id > 65535:
						ip_id = 0

				#actualizarea timestamp-ului daca e cazul
				opt = self.packet[TCP].options
				if opt is not None and len(opt) > 0:	
					for i, (o_name, val) in enumerate(opt):
						if o_name == "Timestamp":
							TS_Current = time.perf_counter()
							TSVal = TS_Base + int((TS_Current - TS_Start) * 1000 / TS_Granularity)
							TSEcr = val[1]
							opt[i] = (o_name, (TSVal, TSEcr))
							break

				sendp(self.packet)
	
	@staticmethod
	def check_all():
		copied_streams = None
		with TCPStream.tcp_streams_lock:
			copied_streams = list(TCPStream.tcp_streams.items())

		for _, stream in copied_streams:
			stream.decrease_timestamp()

	@staticmethod
	def remove_stream(key):
		with TCPStream.tcp_streams_lock:
			if key in TCPStream.tcp_streams:
				del TCPStream.tcp_streams[key]

def periodic_check():
	while True:
		TCPStream.check_all()
		time.sleep(0.01)	


def get_ts_base():
	if op_sys == "WS2025":
		return randint(100000000, 200000000)
	elif op_sys == "WS2012":
		return randint(1000000, 2000000)
	else:
		print("Unknown OS! <get_ts_base>")

def get_ts_granularity():
	if op_sys == "WS2025":
		return 1
	elif op_sys == "WS2012":
		return 10
	else:
		print("Unknown OS! <get_ts_granularity>")

def get_ttl():
	if op_sys == "WS2025":
		return 128
	elif op_sys == "WS2012":
		return 128
	else:
		print("Unknown OS! <get_ttl>")

# ARP request pentru a afla MAC-ul unui IP
def get_mac(ip):
	arp_request = ARP(pdst=ip)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

	arp_request_broadcast = broadcast / arp_request

	answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

	if answered_list:
		arp_table[ip] = answered_list[0][1].hwsrc
		return answered_list[0][1].hwsrc
	else:
		return None

# Incarcarea pachetelor de raspuns
def load_reply_packets():
	for file in os.listdir('responses'):
		packet_number = str(file.split(".pcapng")[0])
		packets = rdpcap(f"responses/{file}")
		reply_packets[packet_number] = packets[0]

def handle_static_packet(packet, prediction, scan_type):
	global ip_id
	dst_mac = arp_table.get(packet[IP].src) if packet[IP].src in arp_table else get_mac(packet[IP].src)
	ether_layer = Ether(dst=dst_mac, src=my_mac, type=0x0800)
	ip_layer = IP(dst=packet[IP].src, src=packet[IP].dst)
	with ip_id_lock:
		ip_layer.id = ip_id
		ip_id += 1
		if ip_id > 65535:
			ip_id = 0
	ip_layer.ttl = ttl
	ip_layer.flags = reply_packets[prediction][IP].flags

	new_packet = None
	is_tcp = False
	if scan_type == 'smb':
		if prediction in ['51']:
			tcp_layer = deepcopy(reply_packets[prediction][TCP])

			# Calcularea noilor valori pentru porturi, seq, ack si eliminarea checksum-ului
			tcp_layer.dport = packet[TCP].sport
			tcp_layer.sport = packet[TCP].dport
			payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
			if payload_len == 0:
				tcp_layer.ack = packet[TCP].seq + 1
			else:
				tcp_layer.ack = packet[TCP].seq + payload_len
			if packet[TCP].ack == 0:
				tcp_layer.seq = randint(1000000000, 4294967295)
			else:
				tcp_layer.seq = packet[TCP].ack
			tcp_layer.window = 0

			del tcp_layer.chksum
			new_packet = ether_layer / ip_layer / tcp_layer
			is_tcp = True
		elif prediction in ['61']:
			udp_layer = deepcopy(reply_packets[prediction][UDP])

			# Calcularea noilor valori pentru porturi si eliminarea checksum-ului
			udp_layer.dport = packet[UDP].sport
			udp_layer.sport = packet[UDP].dport

			del udp_layer.chksum

			new_packet = ether_layer / ip_layer / udp_layer
		else:
			pass
	elif scan_type == 'rdp':
		tcp_layer = deepcopy(reply_packets[prediction][TCP])

		# Calcularea noilor valori pentru porturi, seq, ack si eliminarea checksum-ului
		tcp_layer.dport = packet[TCP].sport
		tcp_layer.sport = packet[TCP].dport
		payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
		if payload_len == 0:
			tcp_layer.ack = packet[TCP].seq + 1
		else:
			tcp_layer.ack = packet[TCP].seq + payload_len
		if packet[TCP].ack == 0:
			tcp_layer.seq = randint(1000000000, 4294967295)
		else:
			tcp_layer.seq = packet[TCP].ack
		tcp_layer.window = 0

		del tcp_layer.chksum
		new_packet = ether_layer / ip_layer / tcp_layer
		is_tcp = True

	if new_packet is not None:
		sendp(new_packet)
		if is_tcp:
			tcp_stream = TCPStream(new_packet, time.perf_counter())
			tcp_stream.add_stream()

# Extrage destport, header length, flags, is http response, options length
def extract_tcp_features(pkt):
	global just_sent_http_response
	dest_port = int(pkt[TCP].dport)
	header_length = int(pkt[TCP].dataofs) * 4
	flags = '0x0002' if pkt[TCP].flags == 'S' else '0x0011'
	is_http_response = False
	if pkt[TCP].flags == 'FA':
		if just_sent_http_response:
			is_http_response = True
	
	opt = pkt[TCP].options
	options_len = 0
	options = {"o_mss" : -1, 
			   "o_wscale" : -1, 
			   "nops" : 0,
			   "o_tstamps" : "False",
			   "o_sack" : "False",
			   "o_eol" : "False"}

	if opt is not None and len(opt) > 0:	
		for (o_name, value) in opt:
			if o_name == "MSS":
				options["o_mss"] = value
				options_len += 4
			elif o_name == "WScale":
				options["o_wscale"] = value
				options_len += 3
			elif o_name == "NOP":
				options["nops"] += 1
				options_len += 1
			elif o_name == "Timestamp":
				options["o_tstamps"] = "True"
				options_len += 10
			elif o_name == "SAckOK":
				options["o_sack"] = "True"
				options_len += 2
			elif o_name == "EOL":
				options["o_eol"] = "True"
				options_len += 1
			elif o_name == "Echo":
				options_len += 6
			elif o_name == "EchoReply":
				options_len += 6
			elif o_name == "POCPermitted":
				options_len += 2
			elif o_name == "POCService":
				options_len += 3
			elif o_name == "AltChkSum":
				options_len += 3
			elif o_name == "AltChkSumOpt":
				options_len += 3
			elif o_name == "MD5":
				options_len += 18
			elif o_name == "QuickStart":
				options_len += 8
			elif o_name == "UTO":
				options_len += 4
			else:
				print(f"Parsing Unknown TCP Option! Name : {o_name}")
	
	options_len = float(options_len)
	tcp_features = [str(dest_port), str(header_length), str(flags), str(is_http_response), str(options_len) 
					, str(options["o_mss"]), str(options["o_wscale"]), str(options["nops"]), str(options["o_tstamps"])
					, str(options["o_sack"]), str(options["o_eol"])]
	tcp_features_df = pd.DataFrame([tcp_features], columns=["dest_port", "header_length", "flags", "is_http_response", "o_len"
														   , "o_mss", "o_wscale", "nops", "o_tstamps", "o_sack", "o_eol"])
	return tcp_features_df

def handle_tcp_packet(packet, prediction):
	global ip_id
	dst_mac = arp_table.get(packet[IP].src) if packet[IP].src in arp_table else get_mac(packet[IP].src)
	ether_layer = Ether(dst=dst_mac, src=my_mac, type=0x0800)
	ip_layer = IP(dst=packet[IP].src, src=packet[IP].dst)
	with ip_id_lock:
		ip_layer.id = ip_id
		ip_id += 1
		if ip_id > 65535:
			ip_id = 0
	ip_layer.ttl = ttl
	if '.' not in prediction:
		ip_layer.flags = reply_packets[prediction][IP].flags

	tcp_layer = None
	generated_seq = randint(1000000000, 4294967295)

	if prediction == '21.51':
		tcp_layer = deepcopy(reply_packets['21'][TCP])
		ip_layer.flags = reply_packets['21'][IP].flags

		# Calcularea noilor valori pentru porturi, seq, ack si eliminarea checksum-ului si lungimii
		tcp_layer.dport = packet[TCP].sport
		tcp_layer.sport = packet[TCP].dport
		payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
		if payload_len == 0:
			tcp_layer.ack = packet[TCP].seq + 1
		else:
			tcp_layer.ack = packet[TCP].seq + payload_len
		if packet[TCP].ack == 0:
			tcp_layer.seq = generated_seq
		else:
			tcp_layer.seq = packet[TCP].ack

		del tcp_layer.chksum

		new_packet = ether_layer / ip_layer / tcp_layer
		#SLEEP 200 MS BEFORE SENDING TO SIMULATE REAL SERVER
		time.sleep(0.2)
		sendp(new_packet)
		#Aici e ACK sec care nu trebuie retransmis in cazul in care nu ajunge
		#tcp_stream = TCPStream(new_packet, time.perf_counter())
		#tcp_stream.add_stream()

		tcp_layer = deepcopy(reply_packets['51'][TCP])
		ip_layer.flags = reply_packets['21'][IP].flags
		with ip_id_lock:
			ip_layer.id = ip_id
			ip_id += 1
			if ip_id > 65535:
				ip_id = 0
	else:
		tcp_layer = deepcopy(reply_packets[prediction][TCP])

	# Calcularea noilor valori pentru porturi, seq, ack si eliminarea checksum-ului
	tcp_layer.dport = packet[TCP].sport
	tcp_layer.sport = packet[TCP].dport
	payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
	if payload_len == 0:
		tcp_layer.ack = packet[TCP].seq + 1
	else:
		tcp_layer.ack = packet[TCP].seq + payload_len
	if packet[TCP].ack == 0:
		tcp_layer.seq = generated_seq
	else:
		tcp_layer.seq = packet[TCP].ack

	# Actualizarea ferestrei pentru porturile 139 si 3389
	if packet[TCP].dport == 139:
		tcp_layer.window = 8192
	if packet[TCP].dport == 3389:
		tcp_layer.window = 64000

	# Calcularea timestamp-ului daca e cazul
	opt = tcp_layer.options
	if opt is not None and len(opt) > 0:	
		for i, (o_name, _) in enumerate(opt):
			if o_name == "Timestamp":
				TS_Current = time.perf_counter()
				TSVal = TS_Base + int((TS_Current - TS_Start) * 1000 / TS_Granularity)
				TSEcr = 0
				packet_opt = packet[TCP].options
				if packet_opt is not None and len(packet_opt) > 0:
					for (p_o_name, p_value) in packet_opt:
						if p_o_name == "Timestamp":
							TSEcr = p_value[0]
							break
				opt[i] = (o_name, (TSVal, TSEcr))
				break

	del tcp_layer.chksum

	new_packet = ether_layer / ip_layer / tcp_layer
	sendp(new_packet)
	if prediction != '21':
		tcp_stream = TCPStream(new_packet, time.perf_counter())
		tcp_stream.add_stream()

def extract_rdp_features(pkt):
	payload = pkt[Raw].load
	
	if len(payload) < 8:
		return None
	
	length = float(int.from_bytes(payload[2:4], byteorder='big'))

	req_protocol = None
	negotiation_offset = payload.find(b'\x01\x00\x08\x00')
	if negotiation_offset != -1:
		req_protocol = int.from_bytes(payload[negotiation_offset + 4:negotiation_offset + 8], byteorder='little')
		if length == 42.0:
			req_protocol = f"0x{req_protocol:08x}"
		else:
			req_protocol = '0x00000016'
	else:
		#cotp simplu
		req_protocol = '0x00000016'
	
	rdp_features = [str(req_protocol), str(length)]
	rdp_features_df = pd.DataFrame([rdp_features], columns=["req_protocol", "tpkt_length"])
	return rdp_features_df

def handle_rdp_packet(packet, prediction):
	global ip_id
	dst_mac = arp_table.get(packet[IP].src) if packet[IP].src in arp_table else get_mac(packet[IP].src)
	ether_layer = Ether(dst=dst_mac, src=my_mac, type=0x0800)
	ip_layer = IP(dst=packet[IP].src, src=packet[IP].dst)
	with ip_id_lock:
		ip_layer.id = ip_id
		ip_id += 1
		if ip_id > 65535:
			ip_id = 0
	ip_layer.ttl = ttl
	if '.' not in prediction:
		ip_layer.flags = reply_packets[prediction][IP].flags

	if prediction == '21.71' or prediction == '21.51':
		tcp_layer = deepcopy(reply_packets['21'][TCP])
		ip_layer.flags = reply_packets['21'][IP].flags
		generated_seq = randint(1000000000, 4294967295)

		# Calcularea noilor valori pentru porturi, seq, ack si eliminarea checksum-ului si lungimii
		tcp_layer.dport = packet[TCP].sport
		tcp_layer.sport = packet[TCP].dport
		payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
		if payload_len == 0:
			tcp_layer.ack = packet[TCP].seq + 1
		else:
			tcp_layer.ack = packet[TCP].seq + payload_len
		if packet[TCP].ack == 0:
			tcp_layer.seq = generated_seq
		else:
			tcp_layer.seq = packet[TCP].ack

		del tcp_layer.chksum

		new_packet = ether_layer / ip_layer / tcp_layer
		#SLEEP 200 MS BEFORE SENDING TO SIMULATE REAL SERVER
		time.sleep(0.2)
		sendp(new_packet)
		tcp_stream = TCPStream(new_packet, time.perf_counter())
		tcp_stream.add_stream()

		with ip_id_lock:
			ip_layer.id = ip_id
			ip_id += 1
			if ip_id > 65535:
				ip_id = 0

		if prediction == '21.71':
			tcp_layer = deepcopy(reply_packets['71'][TCP])
			ip_layer.flags = reply_packets['71'][IP].flags
		else:
			tcp_layer = deepcopy(reply_packets['51'][TCP])
			ip_layer.flags = reply_packets['51'][IP].flags

		# Calcularea noilor valori pentru porturi, seq, ack si eliminarea checksum-ului
		tcp_layer.dport = packet[TCP].sport
		tcp_layer.sport = packet[TCP].dport
		payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
		if payload_len == 0:
			tcp_layer.ack = packet[TCP].seq + 1
		else:
			tcp_layer.ack = packet[TCP].seq + payload_len
		if packet[TCP].ack == 0:
			tcp_layer.seq = generated_seq
		else:
			tcp_layer.seq = packet[TCP].ack

		del tcp_layer.chksum
		if prediction == '21.51':
			tcp_layer.window = 0

		new_packet = ether_layer / ip_layer / tcp_layer
		sendp(new_packet)
		tcp_stream = TCPStream(new_packet, time.perf_counter())
		tcp_stream.add_stream()
	else:
		tcp_layer = deepcopy(reply_packets[prediction][TCP])

		# Calcularea noilor valori pentru porturi, seq, ack si eliminarea checksum-ului
		tcp_layer.dport = packet[TCP].sport
		tcp_layer.sport = packet[TCP].dport
		payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
		if payload_len == 0:
			tcp_layer.ack = packet[TCP].seq + 1
		else:
			tcp_layer.ack = packet[TCP].seq + payload_len
		if packet[TCP].ack == 0:
			tcp_layer.seq = generated_seq
		else:
			tcp_layer.seq = packet[TCP].ack

		del tcp_layer.chksum

		new_packet = ether_layer / ip_layer / tcp_layer
		sendp(new_packet)
		tcp_stream = TCPStream(new_packet, time.perf_counter())
		tcp_stream.add_stream()

def extract_http_features(pkt):
	http_data = pkt[Raw].load.decode("utf-8", errors="ignore")
	http_data = http_data.split("\r\n")
	http_data = http_data[0].split(" ")
	http_data = [http_data[0], http_data[1], http_data[2]]
	http_features_df = pd.DataFrame([http_data], columns=["request_method", "request_uri", "request_version"])
	return http_features_df

def handle_http_packet(packet, prediction):
	global ip_id
	dst_mac = arp_table.get(packet[IP].src) if packet[IP].src in arp_table else get_mac(packet[IP].src)
	ether_layer = Ether(dst=dst_mac, src=my_mac, type=0x0800)
	ip_layer = IP(dst=packet[IP].src, src=packet[IP].dst)
	tcp_layer = deepcopy(reply_packets[prediction][TCP])

	with ip_id_lock:
		ip_layer.id = ip_id
		ip_id += 1
		if ip_id > 65535:
			ip_id = 0
	ip_layer.ttl = ttl

	ip_layer.flags = reply_packets[prediction][IP].flags

	# Calcularea noilor valori pentru porturi, seq, ack si eliminarea checksum-ului si lungimii
	tcp_layer.dport = packet[TCP].sport
	tcp_layer.sport = packet[TCP].dport
	payload_len = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
	if payload_len == 0:
		tcp_layer.ack = packet[TCP].seq + 1
	else:
		tcp_layer.ack = packet[TCP].seq + payload_len
	if packet[TCP].ack == 0:
		tcp_layer.seq = randint(1000000000, 4294967295)
	else:
		tcp_layer.seq = packet[TCP].ack

	del tcp_layer.chksum

	ref_http_layer = deepcopy(reply_packets[prediction][Raw])
	http_payload = ref_http_layer.load.decode("utf-8", errors="ignore")
	current_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
	if "Date:" in http_payload:
		http_payload = http_payload.replace(
			http_payload.split("Date: ")[1].split("\r\n")[0],
			current_date
		)
	http_layer = http_payload.encode("utf-8")

	if Raw in tcp_layer:
		del tcp_layer[Raw]

	new_packet = ether_layer / ip_layer / tcp_layer / http_layer
	sendp(new_packet)


def handle_icmp_packet(packet):
	global ip_id
	dst_mac = arp_table.get(packet[IP].src) if packet[IP].src in arp_table else get_mac(packet[IP].src)
	ether_layer = Ether(dst=dst_mac, src=my_mac, type=0x0800)
	ip_layer = IP(dst=packet[IP].src, src=packet[IP].dst)
	with ip_id_lock:
		ip_layer.id = ip_id
		ip_id += 1
		if ip_id > 65535:
			ip_id = 0
	ip_layer.ttl = ttl

	icmp_layer = deepcopy(packet[ICMP])
	icmp_layer.type = 0
	icmp_layer.code = 0
	del icmp_layer.chksum

	new_packet = ether_layer / ip_layer / icmp_layer
	sendp(new_packet)

# Procesarea pachetelor direct in kernel
def packet_handler(packet):
	''' Ne intereseaza sa prelucram doar pachetele de interes adica TCP SYN, TCP FIN ACK, HTTP GET, HTTP POST 
		Restul le lasam in seama sistemului de operare '''
	global just_sent_http_response
	#print("[INFO] Packet received")

	pkt = IP(packet.get_payload())
	
	if pkt.haslayer(TCP):
		tcp_layer = pkt.getlayer(TCP)

		if tcp_layer.dport in [80, 135, 139, 445, 3389, 5985]:
			src_ip = pkt[IP].src
			src_port = pkt[TCP].sport
			dst_ip = pkt[IP].dst
			dst_port = pkt[TCP].dport
			stream_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
			TCPStream.remove_stream(stream_key)

			if pkt.haslayer(NBTSession):
				nbt_layer = pkt[NBTSession]
				if nbt_layer.haslayer(SMB_Header):
					if smb_model is not None:
						handle_static_packet(pkt, '51', 'smb')
					packet.drop()
			elif pkt.haslayer(Raw):
				if tcp_layer.dport == 3389:
					payload = pkt[Raw].load
					#tls handshake indiferent de versiune
					if payload.startswith(b'\x16'):
						if rdp_model is not None:
							handle_static_packet(pkt, '51', 'rdp')
						packet.drop()
					else:
						if rdp_model is not None:
							rdp_features = extract_rdp_features(pkt)
							if rdp_features is not None:
								rdp_prediction = rdp_model.predict(rdp_features)[0]
								if '.0' in rdp_prediction:
									rdp_prediction = rdp_prediction.split('.0')[0]
								if rdp_prediction != '0':
									handle_rdp_packet(pkt, rdp_prediction)
								packet.drop()
							else:
								packet.drop()
						else:
							packet.drop()
				# HTTP handling (Portul 80)
				if tcp_layer.dport == 80:
					if http_model is not None:
						http_features = extract_http_features(pkt)
						http_prediction = http_model.predict(http_features)[0]
						packet.drop()
						if http_prediction != '0':
							handle_http_packet(pkt, http_prediction)
					else:
						packet.drop()
			elif pkt[TCP].flags == 'S' or pkt[TCP].flags == 'FA' or pkt[TCP].flags == 'SEC':
				tcp_features = extract_tcp_features(pkt)
				tcp_prediction = tcp_model.predict(tcp_features)[0]
				if '.0' in tcp_prediction:
					tcp_prediction = tcp_prediction.split('.0')[0]
				packet.drop()
				if tcp_prediction != '0':
					handle_tcp_packet(pkt, tcp_prediction)
			elif pkt[TCP].flags == 'A' and just_sent_http_response:
				just_sent_http_response = False
				packet.drop()
			else:
				packet.drop()
		else:
			packet.drop()
	elif pkt.haslayer(UDP):
		udp_layer = pkt.getlayer(UDP)

		# NetBIOS Name Service (NBNS) hangling (Portul 137)
		if udp_layer.dport == 137:
			handle_static_packet(pkt, '61', 'smb')
		packet.drop()
	elif pkt.haslayer(ICMP):
		time.sleep(0.030)
		# if ping request handle if not drop
		if pkt[ICMP].type == 8:
			handle_icmp_packet(pkt)
		else:
			packet.drop()
	else:
		packet.drop()

# Setare firewall + nfqueue
def setup_iptables():
	os.system("sudo iptables -F")
	# RST trimis de smb nu va fi blocat pentru ca regula opreste doar RST pure. Raspunsul pentru SMB e un RST ACK
	os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
	os.system("sudo iptables -A INPUT -j NFQUEUE --queue-num 1")
	os.system(f"sudo iptables -t mangle -A OUTPUT -j TTL --ttl-set {ttl}")



# ************************************************
load_reply_packets()

ttl = get_ttl()

nfqueue = NetfilterQueue()
setup_iptables()
nfqueue.bind(1, packet_handler)

TS_Base = get_ts_base()
TS_Granularity = get_ts_granularity()
TS_Start = time.perf_counter()

checker_thread = threading.Thread(target=periodic_check, daemon=True)
checker_thread.start()

try:
	print("[INFO] Waiting for packets...")
	nfqueue.run()
except KeyboardInterrupt:
	os.system("sudo iptables -F")
	os.system("sudo iptables -t mangle -F")
	print("[INFO] Firewall rules cleared.")
# *************************************************
