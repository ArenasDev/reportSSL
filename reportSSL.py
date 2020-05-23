from sslyze import (
	ServerNetworkLocationViaDirectConnection,
	ServerConnectivityTester,
	Scanner,
	ServerScanRequest,
	ScanCommand,
)
from sslyze.errors import ConnectionToServerFailed
from sslyze.errors import ServerHostnameCouldNotBeResolved
import sys
import json
import os
from subprocess import Popen, PIPE
import signal
import PIL
from PIL import ImageFont
from PIL import Image
from PIL import ImageDraw
from prettytable import PrettyTable


class ReportSSL:
	def __init__(self):
		with open('ciphers.json') as j:
			self.ciphers = json.load(j)
		self.parseArgs()
		# self.checkDeprecatedTLS()
		self.downgradePrevention()


	def parseArgs(self):
		if len(sys.argv) == 3:
			try:
				# Define the server that you want to scan
				serverLocation = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(sys.argv[1], sys.argv[2])

				# Do connectivity testing to ensure SSLyze is able to connect
				self.serverInfo = ServerConnectivityTester().perform(serverLocation)
			except ConnectionToServerFailed as e:
				# Could not connect to the server; abort
				print(f"Error connecting to {serverLocation}: {e.error_message}")
				sys.exit()
			except ServerHostnameCouldNotBeResolved:
				print(f"Cannot resolve {sys.argv[1]}, check that it is correct (IP is correct and domain does not include protocol)")
				sys.exit()
			print("Connectivity testing completed")
			self.highestProtocol = self.serverInfo.tls_probing_result.highest_tls_version_supported.name
		else:
			print('Execute: python reportSSL.py www.google.es 443')
			sys.exit()

	def checkDeprecatedTLS(self):
		results = self.initiateScan({ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES})

		keys = {"TLSv1.0" : ScanCommand.TLS_1_0_CIPHER_SUITES, "TLSv1.1" : ScanCommand.TLS_1_1_CIPHER_SUITES}

		for result in results:
			for key in keys.keys():
				try:
					pt = PrettyTable(border=False)
					pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "KeyExch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)"]
					pt.align = 'l'
					tls = result.scan_commands_results[keys[key]]
					
					for cipher in tls.accepted_cipher_suites:
						try:
							elem = self.ciphers[cipher.cipher_suite.name]
							pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name])
						except Exception:
							print(f'Cipher {cipher.cipher_suite.name} not found in database')
					if len(tls.accepted_cipher_suites) > 0:
						self.generateImageAndPrintInfo(f"Accepted cipher suites for {key} (server {sys.argv[1]}):", pt, key)
				except KeyError:
					print(key + ' scan failed')

	def downgradePrevention(self):
		results = self.initiateScan({ScanCommand.TLS_FALLBACK_SCSV})

		for result in results:
			if not result.scan_commands_results[ScanCommand.TLS_FALLBACK_SCSV].supports_fallback_scsv:
				env = os.environ.copy()
				env["PATH"] = os.getcwd() + '\\OpenSSL\\bin;' + env["PATH"]

				protocolFlag = '-no_'
				#Check highest protocol to prevent its use in openssl
				if 'tls' in self.highestProtocol.lower() or 'ssl' in self.highestProtocol.lower():
					protocolFlag += self.highestProtocol.lower().replace('tls_', 'tls').replace('ssl_', 'ssl').replace('_0', '')
				else:
					print('Potentially vulnerable to downgrade attack. Highest supported protocol is not TLS or SSL.')


				p = Popen('openssl.exe s_client -connect ' + sys.argv[1] + ':' + sys.argv[2] + ' -fallback_scsv ' + protocolFlag, env=env, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
				p.send_signal(signal.SIGINT)
				stdout = p.communicate()[0]
				print(stdout.decode())


	def initiateScan(self, commands):
		self.scanner = Scanner()
		serverScanReq = ServerScanRequest(
			server_info = self.serverInfo, scan_commands = commands,
		)
		self.scanner.queue_scan(serverScanReq)

		return self.scanner.get_results()

	def generateImageAndPrintInfo(self, prev, pt, imageName):
		data = ''
		print(prev)
		print('-' * len(prev))
		data += prev + '\n'
		data += '-' * len(prev) + '\n'

		#Delete first whitespace result of deleting borders
		table = str(pt).split('\n')[0][1:] + '\n'
		table += '-' * len(str(pt).split('\n')[0]) + '\n'
		for line in str(pt).split('\n')[1:]:
			table += line[1:] + '\n'
		print(table)
		data += table
		self.text2png(data, imageName + '.png')

	def text2png(self, text, fullpath, color = "#000", bgcolor = "#FFF", fontsize = 30, padding = 10):
		font = ImageFont.truetype("consola.ttf", fontsize)

		width = font.getsize(max(text.split('\n'), key = len))[0] + (padding * 2)
		line_height = font.getsize(text)[1]
		img_height = line_height * (len(text.split('\n')) + 1) + padding
		img = Image.new("RGBA", (width, img_height), bgcolor)
		draw = ImageDraw.Draw(img)

		y = padding
		for line in text.split('\n'):
			draw.text((padding, y), line, color, font=font)
			y += line_height

		img.save(fullpath)





if __name__ == '__main__':
	ReportSSL()
