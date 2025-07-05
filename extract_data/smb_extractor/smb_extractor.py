from ..save_response import save_response

def extract_smb_data(stream_packets, original_pcap):
	''' Cererile SMB si NBNS au mereu acelasi raspuns, vor trebui modificate doar specifile tcp/udp'''
	static_atributes = {'type':['smb', 'nbns']}
	static_attributes_types = ['51', '61']
	for i in range(len(stream_packets)):
		if 'smb' in stream_packets[i]['_source']['layers'] and (i + 1) < len(stream_packets):
			save_response(stream_packets[i + 1], '51', original_pcap)
			break
	return static_atributes, static_attributes_types