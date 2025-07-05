import extract_data
import train_models
import subprocess
import zipfile
import json
import os

def create_archive(output_filename):
	with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as archive:
		files_to_include = ['honeypot.py', 'config.json']
		folders_to_include = ['resulted_models', 'responses']

		for file in files_to_include:
			if os.path.isfile(file):
				archive.write(file, arcname=file)

		for folder in folders_to_include:
			if os.path.isdir(folder):
				for root, dirs, files in os.walk(folder):
					for file in files:
						file_path = os.path.join(root, file)
						archive.write(file_path, arcname=os.path.relpath(file_path, start=os.getcwd()))

if __name__ == "__main__":
	with open('config.json', 'r') as file:
		config = json.load(file)

	protocols = config['protocols']
	train_scans = config['scans']['train']
	test_scans = config['scans']['test']

	print("Generating train database...")
	extract_data.generate_database(train_scans, protocols, type='train')
	if len(test_scans) > 0:
		print("Generating test database...")
		extract_data.generate_database(test_scans, protocols, type='test')
	else:
		print("No test scans provided. Using train scans for testing...")
		extract_data.generate_database(train_scans, protocols, type='test')

	train_models.train_model('tcp')
	for protocol in protocols:
		train_models.train_model(protocol)
		
	print("Training completed.")
	print("Creating archive...")
	create_archive('honeypot.zip')
	print("Archive created successfully.")
	print("Cleaning up...")

	subprocess.run('Clean.bat', shell=True)
	print("Cleanup completed.")