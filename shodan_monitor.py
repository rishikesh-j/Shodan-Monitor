from shodan import Shodan
import os
import fileinput
import json
import argparse

parser = argparse.ArgumentParser(
                    prog = "\n\nShodan Monitor v0.1.\n\n",
                    description = 'An Shodan Dorking Automation Tool.')

parser.add_argument("-i","--input",help="Text file which contains the target or input.",action="store",required=True)
parser.add_argument("-o","--output",default="output",help="Output directory where the result is to be saved.",action="store",required=False)
parser.add_argument("-c","--compare",help="Compare the result with previous ran result to check if any new entry have been made.",action='store_true',required=False)

args = parser.parse_args()

output_dir = args.output

api = Shodan('SHODAN_API_KEY') #Working shodan API key.

print('\n')

def searching_shodan():
	for line in fileinput.FileInput(files = args.input):
		target = line
		replace = "${target}" #Replace part in dork file.

		with open(r'dorks.txt', 'r') as file: #dorks.txt is the file which has all dorks.
			dorks = file.read()
			dorks = dorks.replace(replace, target)

		with open(r'tmp.txt', 'w') as file: #Just a temporary file for code, need to be always present in directory.
			file.write(dorks)

		for line in fileinput.FileInput(files = "tmp.txt"):
			name = line.split("::")[0]
			dork = line.split("::")[1]
			print(f'Dorking for {name}....')
			shodan_search = api.search(dork)
			result = json.dumps(shodan_search)
			filename = output_dir+"/"+target+"/"+name+".json"
			os.makedirs(os.path.dirname(filename), exist_ok=True)
			with open(filename, 'w') as final_results:
				final_results.write(result)

def json_file_ip_compare(old_file, new_file):
	with open(old_file, 'r') as file1:
		data_old = file1.readlines()
		str_old = ""
		json_old = json.loads(str_old.join(data_old))
		result_old = json_old['matches']

	with open(new_file, 'r') as file2:
		data_new = file2.readlines()
		str_new = ""
		json_new = json.loads(str_new.join(data_new))
		result_new = json_new['matches']

	for i in result_new:
		seen_flag = 0
		for j in result_old:
			if i['ip_str'] == j['ip_str']:
				seen_flag = 1
				break
		if seen_flag == 0:
			print(f"[{i['ip_str']}] is a new IP entry.\n")

def json_file_port_compare(old_file, new_file):
	with open(old_file, 'r') as file1:
		data_old = file1.readlines()
		str_old = ""
		json_old = json.loads(str_old.join(data_old))
		result_old = json_old['matches']

	with open(new_file, 'r') as file2:
		data_new = file2.readlines()
		str_new = ""
		json_new = json.loads(str_new.join(data_new))
		result_new = json_new['matches']

	for i in result_new:
		seen_flag = 0
		for j in result_old:
			if i['port'] == j['port']:
				seen_flag = 1
				break
		if seen_flag == 0:
			print(f"[{i['ip_str']}] has a new port [{i['port']}] open.\n")

def comparing_shodan():
	for line in fileinput.FileInput(files = args.input):
		target = line
		replace = "${target}" #Replace part in dork file.

		with open(r'dorks.txt', 'r') as file: #dorks.txt is the file which has all dorks.
			dorks = file.read()
			dorks = dorks.replace(replace, target)

		with open(r'tmp.txt', 'w') as file: #Just a temporary file for code, need to be always present in directory.
			file.write(dorks)

		for line in fileinput.FileInput(files = "tmp.txt"):
			name = line.split("::")[0]
			dork = line.split("::")[1]
			filename = output_dir+"/"+target+"/"+name+".json"

	exist = os.path.exists(filename)
	if exist:
		for line in fileinput.FileInput(files = args.input):
			target = line
			replace = "${target}" #Replace part in dork file.

			with open(r'dorks.txt', 'r') as file: #dorks.txt is the file which has all dorks.
				dorks = file.read()
				dorks = dorks.replace(replace, target)

			with open(r'tmp.txt', 'w') as file: #Just a temporary file for code, need to be always present in directory.
				file.write(dorks)

			for line in fileinput.FileInput(files = "tmp.txt"):
				name = line.split("::")[0]
				dork = line.split("::")[1]
				shodan_search = api.search(dork)
				result = json.dumps(shodan_search)
				filename_new = output_dir+"/"+target+"/"+name+"_new.json"
				os.makedirs(os.path.dirname(filename_new), exist_ok=True)
				with open(filename_new, 'w') as final_results:
					final_results.write(result)

		for line in fileinput.FileInput(files = "tmp.txt"):
			name = line.split("::")[0]
			print(f'Comparing for {name}....')
			filename = output_dir+"/"+target+"/"+name+".json"
			filename_new = output_dir+"/"+target+"/"+name+"_new.json"
			json_file_ip_compare(filename_new, filename)
			json_file_port_compare(filename_new, filename)

	else:
		print("You have no previous data")

if args.input and not args.compare:
	searching_shodan()

if args.compare and args.input:
	comparing_shodan()

print('\n')


