from ..save_response import save_response

def get_nops(options):
	options = options.split(':')
	nops = 0
	index = 0
	while index < len(options):
		o = options[index]
		if o == '01':
			nops += 1
			index += 1
		elif o == '02' or o == '1c':
			index += 4
		elif o == '03' or o =='0a' or o == '0e' or o == '12':
			index += 3
		elif o == '04' or o == '09':
			index += 2
		elif o == '06' or o == '07':
			index += 6
		elif o == '08':
			index += 10
		elif o == '00':
			index += 1
		elif o == '13':
			index += 18
		elif o == '1b':
			index += 8
		else:
			print('Parsing unknown option: ' + o)
			break

	return str(nops)

def get_response_signature(tcp_info):
	result = tcp_info['tcp.flags'] + tcp_info['tcp.hdr_len']
	o_len = '0'
	if 'tcp.options' in tcp_info:
		o_len = str(tcp_info['tcp.options'].count(':') + 1)
	result += o_len

	if 'tcp.options_tree' in tcp_info:
		options = tcp_info['tcp.options_tree']
		if 'tcp.options.mss' in options:
			result += options['tcp.options.mss_tree']['tcp.options.mss_val']
		else:
			result += '-1'
		
		if 'tcp.options.wscale' in options:
			result += options['tcp.options.wscale_tree']['tcp.options.wscale.shift']
		else:
			result += '-1'

		if 'tcp.option.timestamp' in options:
			result += 'True'
		else:
			result += 'False'
		
		if 'tcp.options.sack_perm' in options:
			result += 'True'
		else:
			result += 'False'

		if 'tcp.options.eol' in options:
			result += 'True'
		else:
			result += 'False'
		
		if 'tcp.options.nop' in options:
			result += get_nops(tcp_info['tcp.options'])
		else:
			result += '0'
	else:
		result += '-1-1FalseFalseFalse0'
	
	return result

def extract_tcp_data(stream_packets, original_pcap):
	''' trebuie sa raspund doar la TCP SYN si TCP FIN ACK deci voi cauta doar aceste 2 perechi cerere raspuns '''
	tcp_atributes = {'dest_port':[], 'header_length':[], 'flags':[], 'is_http_response':[], 'o_len':[], \
				     'o_mss':[], 'o_wscale':[], 'nops':[], 'o_tstamps':[], 'o_sack':[], 'o_eol':[]}
	tcp_response_types = []
	index = 0
	while index < len(stream_packets):
		packet = stream_packets[index]
		tcp_info = packet['_source']['layers']['tcp']
		if tcp_info['tcp.flags'] == '0x0002' or tcp_info['tcp.flags'] == '0x08c2' or \
		   tcp_info['tcp.flags'] == '0x0000' or tcp_info['tcp.flags'] == '0x002b' or tcp_info['tcp.flags'] == '0x0010':
			# SYN - pentru IIS, RDP si SMB
			tcp_atributes['dest_port'].append(tcp_info['tcp.dstport'])
			tcp_atributes['header_length'].append(tcp_info['tcp.hdr_len'])
			tcp_atributes['flags'].append(tcp_info['tcp.flags'])
			tcp_atributes['is_http_response'].append('False')
			o_len = 0
			if 'tcp.options' in tcp_info:
				o_len = tcp_info['tcp.options'].count(':') + 1
			tcp_atributes['o_len'].append(str(o_len))
			response_type_sattled = False
			if tcp_info['tcp.flags'] == '0x0002':
				if o_len == 12:
					tcp_response_types.append('11')
					if index + 1 < len(stream_packets):
						save_response(stream_packets[index + 1], '11', original_pcap)
					response_type_sattled = True
				elif o_len == 4:
					tcp_response_types.append('12')
					if index + 1 < len(stream_packets):
						save_response(stream_packets[index + 1], '12', original_pcap)
					response_type_sattled = True
			# --------------------------------------------------------------
			# pentru os sniffing

			if 'tcp.options_tree' in tcp_info:
				options = tcp_info['tcp.options_tree']
				if 'tcp.options.mss' in options:
					tcp_atributes['o_mss'].append(options['tcp.options.mss_tree']['tcp.options.mss_val'])
				else:
					tcp_atributes['o_mss'].append('-1')
				
				if 'tcp.options.wscale' in options:
					tcp_atributes['o_wscale'].append(options['tcp.options.wscale_tree']['tcp.options.wscale.shift'])
				else:
					tcp_atributes['o_wscale'].append('-1')

				if 'tcp.options.timestamp' in options:
					tcp_atributes['o_tstamps'].append('True')
				else:
					tcp_atributes['o_tstamps'].append('False')
				
				if 'tcp.options.sack_perm' in options:
					tcp_atributes['o_sack'].append('True')
				else:
					tcp_atributes['o_sack'].append('False')

				if 'tcp.options.eol' in options:
					tcp_atributes['o_eol'].append('True')
				else:
					tcp_atributes['o_eol'].append('False')
				
				if 'tcp.options.nop' in options:
					tcp_atributes['nops'].append(get_nops(tcp_info['tcp.options']))
				else:
					tcp_atributes['nops'].append('0')
				
				if tcp_info['tcp.flags'] == '0x0000' or tcp_info['tcp.flags'] == '0x002b' or tcp_info['tcp.flags'] == '0x0010':
					tcp_response_types.append('0')
					break

				if tcp_info['tcp.flags'] == '0x08c2':
					tcp_response_types.append('13')
					if index + 1 < len(stream_packets):
						save_response(stream_packets[index + 1], '13', original_pcap)
					break
				
				if not response_type_sattled:
					if index + 1 < len(stream_packets):
						signature = get_response_signature(stream_packets[index + 1]['_source']['layers']['tcp'])
						tcp_response_types.append(signature)
						save_response(stream_packets[index + 1], signature, original_pcap)
						break
					else:
						print('Parsing strange TCP packet (No response where it should be)! Considered as no response needed!')
						tcp_response_types.append('0')
						break
			else:
				tcp_atributes['o_mss'].append('-1')
				tcp_atributes['o_wscale'].append('-1')
				tcp_atributes['o_tstamps'].append('False')
				tcp_atributes['o_sack'].append('False')
				tcp_atributes['o_eol'].append('False')
				tcp_atributes['nops'].append('0')
				print('Parsing strange TCP packet (No options)! Considered as no response needed!')
				tcp_response_types.append('0')
				break

			# raspunsul e in pachetul urmator asa ca il putem sari
			index += 1
		elif tcp_info['tcp.flags'] == '0x0011':
			# FIN ACK (doar pentru IIS, RDP si SMB)
			tcp_atributes['dest_port'].append(tcp_info['tcp.dstport'])
			tcp_atributes['header_length'].append(tcp_info['tcp.hdr_len'])
			tcp_atributes['flags'].append('0x0011')
			tcp_atributes['o_len'].append('0')
			tcp_atributes['o_mss'].append('-1')
			tcp_atributes['o_wscale'].append('-1')
			tcp_atributes['o_tstamps'].append('False')
			tcp_atributes['o_sack'].append('False')
			tcp_atributes['o_eol'].append('False')
			tcp_atributes['nops'].append('0')
			if int(tcp_info['tcp.dstport']) == 80:
				# pentru http
				if 'http' in stream_packets[index - 1]['_source']['layers']:
					tcp_atributes['is_http_response'].append('True')
					tcp_response_types.append('22')
					if index + 1 < len(stream_packets):
						save_response(stream_packets[index + 1], '22', original_pcap)
				else:
					tcp_atributes['is_http_response'].append('False')
					tcp_response_types.append('21')
					if index + 1 < len(stream_packets):
						save_response(stream_packets[index + 1], '21', original_pcap)
				index += 1
			elif int(tcp_info['tcp.dstport']) == 3389:
				# pentru rdp
				tcp_atributes['is_http_response'].append('False')
				tcp_response_types.append('21.51')
				if index + 2 < len(stream_packets):
					save_response(stream_packets[index + 1], '21', original_pcap)
					save_response(stream_packets[index + 2], '51', original_pcap)
				index += 2
		index += 1
	return tcp_atributes, tcp_response_types