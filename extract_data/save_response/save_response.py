from pathlib import Path
import subprocess

def save_response(response, response_name, original_pcap):
	response_file = Path(__file__).parent.parent.parent / f'responses/{response_name}.pcapng'
	
	if not response_file.exists() and original_pcap is not None:
		frame_number = response['_source']['layers']['frame']['frame.number']

		command = [
			'tshark',
			'-r', original_pcap,
			'-Y', f'frame.number == {frame_number}',
			'-w', str(response_file)
		]
		
		result = subprocess.run(command, capture_output=True, text=True)
		
		if result.returncode != 0:
			raise Exception(f"Tshark error: {result.stderr}")

def rename_response(old_response, new_response): 
	response_file = Path(__file__).parent.parent.parent / f'responses/{old_response}.pcapng'
	new_response_file = Path(__file__).parent.parent.parent / f'responses/{new_response}.pcapng'
	
	response_file = response_file.resolve()
	new_response_file = new_response_file.resolve()
	
	if not response_file.exists():
		raise FileNotFoundError(f"Renaiming non-existent file: {response_file}")
	
	response_file.rename(new_response_file)