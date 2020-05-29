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
import time
import threading
import PIL
from PIL import ImageFont
from PIL import Image
from PIL import ImageDraw
from prettytable import PrettyTable


class ReportSSL:
	def __init__(self):
		self.output = ''
		self.imageFolder  = 'images'
		with open('ciphers.json') as j:
			self.ciphers = json.load(j)
		self.parseArgs()
		self.getAllCiphers()
		# self.certificate()
		# self.deprecatedTLS()
		# self.TLSv1_3()
		# self.downgradePrevention()
		# self.OCSPStapling()
		# self.specificAlg('RC4', None, 'Accepted RC4 cipher suites', 'RC4')
		# self.specificAlg('3DES', None, 'Server is vulnerable to SWEET32 attacks because it supports block-based algorithms with block size of 64 (3DES)', 'SWEET32')
		# self.specificAlg('CBC', ["SSLv2",  "SSLv3", "TLSv1.0"], 'Server is vulnerable to BEAST attacks.\nIt supports block-based algorithms (CBC) in SSLv2, SSLv3 or TLSv1.0', 'BEAST')
		# self.specificAlg('CBC', ["SSLv3"], 'Server is vulnerable to POODLE attacks.\nIt supports block-based algorithms (CBC) in SSLv3', 'POODLE')
		# self.drown()
		# self.specificAlg('CBC', ["TLSv1.0", "TLSv1.1", "TLSv1.2"], 'Server is vulnerable to LUCKY13 attacks.\nIt supports block-based algorithms (CBC) in TLS', 'LUCKY13')
		self.logjam()


	'''
	CRIME ->  Deflate / GZIP compression in particular Lz77
	FREAK ->  512 bit RSA-export keys
	BREACH -> Deflate / GZIP compression
	LOGJAM -> cipher suits the use the Diffie-Hellman key exchange and deploy ECDHE, FFDHE groups (TLS 1\\.2)
	SLOTH -> TLS 1.2, RSA-MD5 SIGNATURE
	HEARTBLEED
	ROBOT -> TLS RCA
	ZOMBIE
	GOLDENDOODLE
	cipher order
	secure renegotiation
	'''

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

	def getAllCiphers(self):
		self.allCiphers = {}
		results = self.initiateScan({ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES})
		keys = {"SSLv2" : ScanCommand.SSL_2_0_CIPHER_SUITES, "SSLv3" : ScanCommand.SSL_3_0_CIPHER_SUITES, "TLSv1.0" : ScanCommand.TLS_1_0_CIPHER_SUITES, "TLSv1.1" : ScanCommand.TLS_1_1_CIPHER_SUITES, "TLSv1.2" : ScanCommand.TLS_1_2_CIPHER_SUITES, "TLSv1.3" : ScanCommand.TLS_1_3_CIPHER_SUITES}

		print('Retrieving ciphers for each protocol')
		for result in results:
			for key in keys.keys():
				self.allCiphers.update({key : []})
				try:
					tls = result.scan_commands_results[keys[key]]
					for cipher in tls.accepted_cipher_suites:
						try:
							elem = self.ciphers[cipher.cipher_suite.name]
							# print(cipher.cipher_suite)
							self.allCiphers[key].append(cipher)
						except Exception:
							print(f'Cipher {cipher.cipher_suite.name} not found in database')
				except KeyError:
					print(key + ' scan failed')

	#check
	def certificate(self):
		results = self.initiateScan({ScanCommand.CERTIFICATE_INFO})

		for result in results:
			for cert in result.scan_commands_results[ScanCommand.CERTIFICATE_INFO].certificate_deployments:
				#Check if hostname matches certificate name
				if not cert.leaf_certificate_subject_matches_hostname:
					data = 'Hostname: ' + result.scan_commands_results[ScanCommand.CERTIFICATE_INFO].hostname_used_for_server_name_indication + '\n'
					data += 'Certificate name: ' + str(result.scan_commands_results[ScanCommand.CERTIFICATE_INFO].certificate_deployments[0].received_certificate_chain[0].subject).replace('<Name(', '').replace(')>', '').split('CN=')[1].split(',')[0] + '\n'
					self.generateImageAndPrintInfo('Certificate is not trusted because it does not match hostname', data, 'CertificateUntrustedNameMismatch', None, None)
				
	def deprecatedTLS(self):
		keys = ["TLSv1.0", "TLSv1.1"]

		for key in keys:
			try:
				pt = PrettyTable(border=False)
				pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)"]
				pt.align = 'l'
				ciphers = self.allCiphers[key]
				
				for cipher in ciphers:
					try:
						elem = self.ciphers[cipher.cipher_suite.name]
						pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name])
					except Exception:
						print(f'Cipher {cipher.cipher_suite.name} not found in database')
				if len(ciphers) > 0:
					self.generateImageAndPrintInfo(f"Accepted cipher suites for {key} (server {sys.argv[1]}):", pt, key, 0, 1 + len(str(pt).split('\n')))
			except KeyError:
				print(key + ' scan failed')

	def specificAlg(self, alg, protos, header, fileName):
		pt = PrettyTable(border=False)
		pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)"]
		pt.align = 'l'
		check = False
		#if no protocol is specified, check all
		if protos == None:
			protos = self.allCiphers.keys()
		for key in protos:
			pt.add_row([key, '', '', '', '', ''])
			for cipher in self.allCiphers[key]:
				elem = self.ciphers[cipher.cipher_suite.name]
				if alg in cipher.cipher_suite.name:
					check = True
					pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name])

		if check:
			self.generateImageAndPrintInfo(f"{header} (server {sys.argv[1]}):", pt, fileName, None, None)

	def drown(self):
		if len(self.allCiphers["SSLv2"]) > 0:
			print('ciphers in SSLv2')
			pt = PrettyTable(border=False)
			pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)"]
			pt.align = 'l'
			for cipher in self.allCiphers["SSLv2"]:
				elem = self.ciphers[cipher.cipher_suite.name]
				pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name])

			self.generateImageAndPrintInfo(f"Server is vulnerable to DROWN attacks because it supports SSLv2 (server {sys.argv[1]}):", pt, 'DROWN', None, None)

	def logjam(self):
		pt = PrettyTable(border=False)
		pt.field_names = ["Hexcode", "Cipher Suite Name (OpenSSL)", "Key Exch.", "Encryption", "Bits", "Cipher Suite Name (IANA/RFC)", "Key Size", "Key Ex. Type"]
		pt.align = 'l'
		check = False
		for key in ["TLSv1.0", "TLSv1.1", "TLSv1.2"]:
			pt.add_row([key, '', '', '', '', '', '', ''])
			for cipher in self.allCiphers[key]:
				elem = self.ciphers[cipher.cipher_suite.name]
				if '_DHE_' in cipher.cipher_suite.name and cipher.ephemeral_key.size <= 1024:
					check = True
					pt.add_row([elem[1], elem[0], elem[2], elem[3], elem[4], cipher.cipher_suite.name, cipher.ephemeral_key.size, cipher.ephemeral_key.type])

		if check:
			self.generateImageAndPrintInfo(f"Server is vulnerable to LOGJAM attacks.\nIt supports Ephemeral Diffie-Hellman algorithms (EDH) with key sizes of 1024 or lower (server {sys.argv[1]}):", pt, 'LOGJAM', None, None)

	def TLSv1_3(self):
		if len(self.allCiphers["TLSv1.3"]) == 0:
			self.generateImageAndPrintInfo('Server does not support TLSv1.3', 'The server does not support TLSv1.3 which is the only version of TLS that currently has no known flaws or exploitable weaknesses.\nHighest supported protocol is ' + self.highestProtocol.replace('TLS_', 'TLSv').replace('SSL_', 'SSLv').replace('_', '.'), 'TLSv1.3NotSupported', None, None)

	def downgradePrevention(self):
		results = self.initiateScan({ScanCommand.TLS_FALLBACK_SCSV})

		for result in results:
			if not result.scan_commands_results[ScanCommand.TLS_FALLBACK_SCSV].supports_fallback_scsv:
				protocolFlag = '-no_'
				#Check highest protocol to prevent its use in openssl
				if 'tls' in self.highestProtocol.lower() or 'ssl' in self.highestProtocol.lower():
					protocolFlag += self.highestProtocol.lower().replace('tls_', 'tls').replace('ssl_', 'ssl').replace('_0', '')
				else:
					print('Potentially vulnerable to downgrade attack. Highest supported protocol is not TLS or SSL.')


				self.finishOpenSSL = threading.Event()
				self.output = ''
				p = Popen(os.getcwd() + '\\OpenSSL\\bin\\openssl.exe s_client -connect ' + sys.argv[1] + ':' + sys.argv[2] + ' -fallback_scsv ' + protocolFlag, stdin=PIPE, stdout=PIPE, stderr=PIPE)
				t = threading.Thread(target=self.outputReader, args=(p, 'Master-Key'))
				t.start()

				while not self.finishOpenSSL.is_set():
					time.sleep(1)
				p.terminate()

				#Handle output to make image
				data = 'Command: openssl.exe s_client -connect ' + sys.argv[1] + ':' + sys.argv[2] + ' -fallback_scsv ' + protocolFlag + '\n\n'
				data += self.output.split('-----BEGIN CERTIFICATE-----')[0]
				data += '[redacted]'
				data += self.output.split('-----END CERTIFICATE-----')[1]

				index = None
				for line in range(len(data)):
					if 'New,' in data[line] and ', Cipher is ' in data[line]:
						index = line

				self.generateImageAndPrintInfo(f"Downgrade prevention is not provided (server {sys.argv[1]}):", data, 'downgradePrevention', index, index)

	def OCSPStapling(self):
		self.finishOpenSSL = threading.Event()
		self.output = ''
		p = Popen(os.getcwd() + '\\OpenSSL\\bin\\openssl.exe s_client -connect ' + sys.argv[1] + ':' + sys.argv[2] + ' -status', stdin=PIPE, stdout=PIPE, stderr=PIPE)
		t = threading.Thread(target=self.outputReader, args=(p, '-----BEGIN CERTIFICATE-----'))
		t.start()

		while not self.finishOpenSSL.is_set():
			time.sleep(1)
		p.terminate()

		for line in self.output.split('\n'):
			if 'OCSP response: no response sent' in line:
				self.generateImageAndPrintInfo(f"OCSP Stapling not supported (server {sys.argv[1]}):", '\n'.join(self.output.split('\n')[:self.output.split('\n').index('-----BEGIN CERTIFICATE-----')]), 'OCSPStaplingNotSupported', self.output.split('\n').index(line), self.output.split('\n').index(line))
				break

	def outputReader(self, proc, finish):
		for line in iter(proc.stdout.readline, b''):
			if finish in line.decode('utf-8'):
				self.finishOpenSSL.set()
			self.output += '{0}'.format(line.decode('utf-8'))

	def initiateScan(self, commands):
		self.scanner = Scanner()
		serverScanReq = ServerScanRequest(
			server_info = self.serverInfo, scan_commands = commands,
		)
		self.scanner.queue_scan(serverScanReq)

		return self.scanner.get_results()

	def generateImageAndPrintInfo(self, prev, pt, imageName, startLine, endLine):
		data = ''
		print(prev)
		if len(prev.split('\n')) > 1:
			print('-' * len(prev.split('\n')[-1]))
		else:
			print('-' * len(prev))
		data += prev + '\n'
		data += '-' * len(prev) + '\n'

		#Delete first whitespace result of deleting borders
		if isinstance(pt, PrettyTable):
			table = str(pt).split('\n')[0][1:] + '\n'
			table += '-' * len(str(pt).split('\n')[0]) + '\n'
			for line in str(pt).split('\n')[1:]:
				table += line[1:] + '\n'
			print(table)
			data += table
		else:
			print(pt)
			data += pt
		self.text2png(data, self.imageFolder + '/' + imageName + '(' + sys.argv[1] + '_' + sys.argv[2] + ').png', startLine = startLine, endLine = endLine)

	def text2png(self, text, fullpath, color = "#000", bgcolor = "#FFF", fontsize = 30, padding = 10, startLine = None, endLine = None):
		font = ImageFont.truetype("consola.ttf", fontsize)

		width = font.getsize(max(text.split('\n'), key = len))[0] + (padding * 2)
		lineHeight = font.getsize(text)[1]
		imgHeight = lineHeight * (len(text.split('\n')) + 1) + padding
		img = Image.new("RGBA", (width, imgHeight), bgcolor)
		draw = ImageDraw.Draw(img)

		y = padding
		#Draw the text
		for line in text.split('\n'):
			draw.text((padding, y), line, color, font=font)
			y += lineHeight

		#Draw the highlight rectangle, have to use line instead of rectangle because it does not support line THICCness
		if startLine != None and endLine != None and endLine >= startLine:
			#Add 2 to each bound because of the two heading lines
			if startLine == endLine:
				endLine += 1
			startLine += 2
			endLine += 2
			point1 = (3, (padding / 2) + 3 + lineHeight * startLine)
			point2 = (3 + font.getsize(text.split('\n')[startLine])[0] + padding, (padding / 2) + 3 + lineHeight * startLine)
			point3 = (3 + font.getsize(text.split('\n')[startLine])[0] + padding, padding + 3 + lineHeight * (startLine + (endLine - startLine)))
			point4 = (3, padding + 3 + lineHeight * (startLine + (endLine - startLine)))
			draw.line((point1, point2, point3, point4, point1), fill="red", width=5)

		if not os.path.exists(self.imageFolder):
			os.makedirs(self.imageFolder)

		img.save(fullpath, quality=100)

if __name__ == '__main__':
	ReportSSL()
