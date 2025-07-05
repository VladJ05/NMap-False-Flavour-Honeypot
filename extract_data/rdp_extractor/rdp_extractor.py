from ..save_response import save_response

def extract_rdp_data(stream_packets, original_pcap):
	rdp_atributes = {}
	rdp_response_type = '0'
	for i, packet in enumerate(stream_packets):
		if 'rdp' in packet['_source']['layers']:
			tpkt_info = packet['_source']['layers']['tpkt']
			rdp_info = packet['_source']['layers']['rdp']
			rdp_atributes['tpkt_length'] = tpkt_info['tpkt.length']

			if int(tpkt_info['tpkt.length']) == 42: 
				rdp_atributes['req_protocol'] = rdp_info['rdp.negReq.requestedProtocols']
				match rdp_info['rdp.negReq.requestedProtocols']:
					case '0x00000003':
						rdp_response_type = '21.71'
						if i + 2 < len(stream_packets):
							save_response(stream_packets[i + 1], '21', original_pcap)
							save_response(stream_packets[i + 2], '71', original_pcap)
					case '0x00000004':
						rdp_response_type = '72'
						if i + 1 < len(stream_packets):
							save_response(stream_packets[i + 1], '72', original_pcap)
					case '0x00000008':
						rdp_response_type = '73'
						if i + 1 < len(stream_packets):
							save_response(stream_packets[i + 1], '73', original_pcap)
					case '0x00000000':
						rdp_response_type = '74'
						if i + 1 < len(stream_packets):
							save_response(stream_packets[i + 1], '74', original_pcap)
					case '0x00000001':
						rdp_response_type = '75'
						if i + 1 < len(stream_packets):
							save_response(stream_packets[i + 1], '75', original_pcap)
			else:
				rdp_atributes['req_protocol'] = '0x00000016' # tehnic valoare imposibila standard
				rdp_response_type = '51'
				if i + 1 < len(stream_packets):
					save_response(stream_packets[i + 1], '51', original_pcap)
			break
		elif 'cotp' in packet['_source']['layers']:
			tpkt_info = packet['_source']['layers']['tpkt']
			rdp_atributes['req_protocol'] = '0x00000016' # tehnic valoare imposibila standard
			rdp_atributes['tpkt_length'] = tpkt_info['tpkt.length']
			rdp_response_type = '21.51'
			if i + 2 < len(stream_packets):
				save_response(stream_packets[i + 1], '21', original_pcap)
				save_response(stream_packets[i + 2], '51', original_pcap)
			break
			
	return rdp_atributes, rdp_response_type