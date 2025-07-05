from ..save_response import save_response

def extract_http_data(stream_packets, original_pcap):
	''' 100% primul pachet http va fi request-ul, iar al doilea va fi response-ul 
		+ exista doar un request si un response in stream '''
	http_atributes = {}
	http_response_type = 0
	is_first = True
	for packet in stream_packets:
		if 'http' in packet['_source']['layers']:
			http_info = packet['_source']['layers']['http']
			if is_first:
				# request-ul
				is_first = False
				k = ''
				for key in http_info:
					if key.startswith('GET') or key.startswith('POST'):
						k = key
						break
				# extragerea celor 3 atribute de interes
				http_atributes['request_method'] = http_info[k]['http.request.method']
				http_atributes['request_uri'] = http_info[k]['http.request.uri']
				http_atributes['request_version'] = http_info[k]['http.request.version']
			else:
				# reply-ul
				k = ''
				for key in http_info:
					if key.startswith('HTTP'):
						k = key
						break
				if http_info[k]['http.response.code'] == '200':
					http_response_type = '31'
					save_response(packet, '31', original_pcap)
				elif http_info[k]['http.response.code'] == '404':
					http_response_type = '41'
					save_response(packet, '41', original_pcap)
				else:
					print("Parsing unknown HTTP status code")
				# dupa ce am gasit raspunsul, ne putem opri
				break
	return http_atributes, http_response_type