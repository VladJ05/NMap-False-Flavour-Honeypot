from .save_response import rename_response
from . import http_extractor
from . import tcp_extractor
from . import rdp_extractor
from . import smb_extractor
from pathlib import Path
import pandas as pd
import subprocess
import json

def get_streams(capture):
	''' Separa pachetele in stream-uri si le sorteaza dupa timestamp 
		Returneaza un dictionar cu key = indexul streamului si value = 
		lista de pachete din stream '''
	
	streams_packets = {}

	for packet in capture:
		try:
			if 'tcp' in packet['_source']['layers'] and 'tcp.stream' in packet['_source']['layers']['tcp']:
				tcp_stream = packet['_source']['layers']['tcp']['tcp.stream']
				if tcp_stream not in streams_packets:
					streams_packets[tcp_stream] = []
				streams_packets[tcp_stream].append(packet)
		except AttributeError:
			continue
	
	for stream, packets in streams_packets.items():
		streams_packets[stream] = sorted(packets, key=lambda x: x['_source']['layers']['frame']['frame.time_epoch'])
	
	# TODO : Think abot this: verify that the streams contains between 2 and 10 packets
	streams_packets = {stream: packets for stream, packets in streams_packets.items() if len(packets) >= 2 and len(packets) <= 10}
	
	return streams_packets

def get_tcp_data_from_streams(streams_packets, original_pcap):
	tcp_atributes = {'dest_port':[], 'header_length':[], 'flags':[], 'is_http_response':[], 'o_len':[], \
				     'o_mss':[], 'o_wscale':[], 'nops':[], 'o_tstamps':[], 'o_sack':[], 'o_eol':[]}
	tcp_data = []
	for stream_packet in streams_packets.values():
		tcp_atributes, tcp_response_types = tcp_extractor.extract_tcp_data(stream_packet, original_pcap)
		for i in range(len(tcp_atributes['dest_port'])):
			tcp_data.append([tcp_atributes['dest_port'][i], tcp_atributes['header_length'][i], tcp_atributes['flags'][i],
							 tcp_atributes['is_http_response'][i], tcp_atributes['o_len'][i], tcp_atributes['o_mss'][i],
							 tcp_atributes['o_wscale'][i], tcp_atributes['nops'][i], tcp_atributes['o_tstamps'][i],
							 tcp_atributes['o_sack'][i], tcp_atributes['o_eol'][i], tcp_response_types[i]])
	return tcp_data

def get_http_data_from_streams(streams_packets, original_pcap):
	# TODO : Think what happens if http stream contains more than 2 packets
	http_data = []
	for stream_packet in streams_packets.values():
		http_atributes, http_response_type = http_extractor.extract_http_data(stream_packet, original_pcap)
		if http_response_type != 0:
			http_data.append([http_atributes['request_method'], http_atributes['request_uri'], http_atributes['request_version'], http_response_type])
	return http_data

def get_rdp_data_from_streams(streams_packets, original_pcap):
	rdp_data = []
	for stream_packet in streams_packets.values():
		rdp_atributes, rdp_response_type = rdp_extractor.extract_rdp_data(stream_packet, original_pcap)
		if rdp_response_type != '0':
			rdp_data.append([rdp_atributes['req_protocol'], rdp_atributes['tpkt_length'], rdp_response_type])
	return rdp_data

def get_smb_data_from_streams(streams_packets, original_pcap):
	smb_data = []
	for stream_packet in streams_packets.values():
		smb_atributes, smb_response_type = smb_extractor.extract_smb_data(stream_packet, original_pcap)
		for i in range(2):
			smb_data.append([smb_atributes['type'][i], smb_response_type[i]])
	return smb_data

def get_data(captures, protocols, original_pcaps):
	response = []
	tcp_data = [['dest_port', 'header_length', 'flags', 'is_http_response', 'o_len', 'o_mss', 'o_wscale', 'nops', 'o_tstamps', 'o_sack', 'o_eol', 'response_type']]
	http_data = [['request_method', 'request_uri', 'request_version', 'response_type']]
	rdp_data = [['req_protocol', 'tpkt_length', 'response_type']]
	smb_data = [['type', 'response_type']]
	for capture, original_pacp in zip(captures, original_pcaps):
		streams_packets = get_streams(capture)
		tcp_data_capture = get_tcp_data_from_streams(streams_packets, original_pacp)
		tcp_data.extend(tcp_data_capture)

		if 'http' in protocols:
			http_data_capture = get_http_data_from_streams(streams_packets, original_pacp)
			http_data.extend(http_data_capture)
		
		if 'rdp' in protocols:
			rdp_data_capture = get_rdp_data_from_streams(streams_packets, original_pacp)
			rdp_data.extend(rdp_data_capture)
		
		if 'smb' in protocols:
			smb_data_capture = get_smb_data_from_streams(streams_packets, original_pacp)
			smb_data.extend(smb_data_capture)

	response.append(('tcp', tcp_data))
	if 'http' in protocols:
		response.append(('http', http_data))
	if 'rdp' in protocols:
		response.append(('rdp', rdp_data))
	if 'smb' in protocols:
		response.append(('smb', smb_data))
	return response

def save_data_to_csv(data, filename):
	df = pd.DataFrame(data[1:], columns=data[0])
	df.to_csv(filename, index=False)

def solve_pottential_unsolved_response_types(tcp_data, type):
	''' pentru a rezolva problema in cazul os_sniifing.
	    sunt 5 raspunsuri care pot fi clasificate diferit in functie de scanare
	    ca sa nu hardcodez, clasificarea se a face automat in functie de datele colectate '''
	
	next_response_type_available = 4
	grouped_bad_response_types = {}
	i = 1
	while i < len(tcp_data):
		if tcp_data[i][11][0:2] == '0x':
			if tcp_data[i][11] not in grouped_bad_response_types:
				grouped_bad_response_types[tcp_data[i][11]] = []
			grouped_bad_response_types[tcp_data[i][11]].append(i)
		i += 1

	if len(grouped_bad_response_types) == 0:
		return tcp_data
	
	for _, indexes in grouped_bad_response_types.items():
		new_name = '1' + str(next_response_type_available)
		renamed = False if type == 'train' else True
		for index in indexes:
			if not renamed:
				rename_response(tcp_data[index][11], new_name)
				renamed = True
			tcp_data[index][11] = new_name
		next_response_type_available += 1
	
	return tcp_data

def extract_packets_with_tshark(pcap_file):
    command = ['tshark', '-r', pcap_file, '-T', 'json']
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"Tshark error: {result.stderr}")
    
    return json.loads(result.stdout)

def generate_database(scans, protocols, type = 'train'):
	captures = []
	original_pcaps = []
	for file in scans:
		pcap_file = Path(__file__).parent.parent / f'scans/{file}'
		packets = extract_packets_with_tshark(pcap_file)
		captures.append(packets)
		if type == 'train':
			original_pcaps.append(pcap_file)
		else:
			original_pcaps.append(None)

	data = get_data(captures, protocols, original_pcaps)
	for protocol, protocol_data in data:
		if protocol == 'tcp':
			tcp_data = protocol_data
			tcp_data = solve_pottential_unsolved_response_types(tcp_data, type)
			file_path = Path(__file__).parent.parent / f'resulted_datasets/tcp_{type}.csv'
			save_data_to_csv(tcp_data, file_path)
		elif protocol == 'http':
			http_data = protocol_data
			file_path = Path(__file__).parent.parent / f'resulted_datasets/http_{type}.csv'
			save_data_to_csv(http_data, file_path)
		elif protocol == 'rdp':
			rdp_data = protocol_data
			file_path = Path(__file__).parent.parent / f'resulted_datasets/rdp_{type}.csv'
			save_data_to_csv(rdp_data, file_path)
		elif protocol == 'smb':
			smb_data = protocol_data
			file_path = Path(__file__).parent.parent / f'resulted_datasets/smb_{type}.csv'
			save_data_to_csv(smb_data, file_path)