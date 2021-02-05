import discord
import os
import requests
import json
import time
import re
from bs4 import BeautifulSoup as bs
from requests_html import AsyncHTMLSession
import asyncio

mySemaphore = asyncio.Semaphore(value=2)
masterClock = 0
count = 4
client = discord.Client()
domainErrors = []
delay = {}
executeOnceCounter = 0
startTime = 0

def get_quote():
	response = requests.get("https://zenquotes.io/api/random")
	json_data = json.loads(response.text)
	quote = json_data[0]['q'] + " - " + json_data[0]['a']
	return(quote)

async def DomainScanner(domain, semaphore):
	apikey = str('VirusTotalAPIKey')
	url = 'https://www.virustotal.com/vtapi/v2/url/scan'
	params = {'apikey': apikey, 'url': domain}
	await semaphore.acquire()
	print("Successfully acquired the semaphore")
	# attempt connection to VT API and save response as r
	global count
	global masterClock
	global executeOnceCounter
	global startTime

	if executeOnceCounter == 0:
		startTime = time.perf_counter()
		executeOnceCounter+=1

	if count == 0:
		masterClock = time.perf_counter() - startTime
		print("API quota reached (scanning)! Sleeping...")
		if masterClock <= 60:
			time.sleep(60 - masterClock)
		elif masterClock > 60:
			print("Sleeping for 20 seconds...")
			time.sleep(20)
		count = 4
		masterClock = 0
		executeOnceCounter = 0
		startTime = time.perf_counter()
		print("Quota reset!")
	try:
		r = requests.post(url, params=params)
		count -= 1
	except requests.ConnectTimeout as timeout:
		print('Connection timed out. Error is as follows-')
		print(timeout)

	# sanitize domain after upload for safety
	domainSani = domain.replace('.', '[.]')
	# handle ValueError response which may indicate an invalid key or an error with scan
	# if an except is raised, add the domain to a list for tracking purposes
	if r.status_code == 200:
		try:
			jsonResponse = r.json()
			# print error if the scan had an issue
			if jsonResponse['response_code'] is not 1:
				print('There was an error submitting the domain for scanning.')
				print(jsonResponse['verbose_msg'])
			elif jsonResponse['response_code'] == -2:
				print('{!s} is queued for scanning.'.format(domainSani))
				delay[domain] = 'queued'
			else:
				print('{!s} was scanned successfully.'.format(domainSani))

		except ValueError:
			print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
			domainErrors.append(domain)
		# return domain errors for notifying user when script completes

	# API TOS issue handling
	elif r.status_code == 204:
		print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit.')
		print('https://support.virustotal.com/hc/en-us/articles/115002118525-The-4-requests-minute-limitation-of-the-'
			  'Public-API-is-too-low-for-me-how-can-I-have-access-to-a-higher-quota-')
	
	if delay:
		if domain in delay:
			print('There was a delay in scanning. Waiting for 10s to ensure the report is ready.')
			await asyncio.sleep(10)

	await asyncio.sleep(30)

	url = 'https://www.virustotal.com/vtapi/v2/url/report'
	params = {'apikey': apikey, 'resource': domain}

	if executeOnceCounter == 0:
		startTime = time.perf_counter()
		executeOnceCounter+=1	
	# attempt connection to VT API and save response as r
	if count == 0:
		masterClock = time.perf_counter() - startTime
		print("API quota reached (reporting)! Sleeping...")
		if masterClock <= 60:
			time.sleep(60 - masterClock)
		elif masterClock > 60:
			print("Sleeping for 20 seconds...")
			time.sleep(20)
		count = 4
		masterClock = 0
		executeOnceCounter = 0
		startTime = time.perf_counter()
		print("Quota reset!")

	try:
		r = requests.post(url, params=params)
		count -= 1
	except requests.ConnectTimeout as timeout:
		print('Connection timed out. Error is as follows-')
		print(timeout)
		exit(1)

	# sanitize domain after upload for safety
	domainSani = "**" + domain.replace('.', '[.]') + "**"
	# handle ValueError response which may indicate an invalid key or an error with scan
	# if an except is raised, add the domain to a list for tracking purposes
	if r.status_code == 200:
		try:
			jsonResponse = r.json()
			# print error if the scan had an issue
			if jsonResponse['response_code'] is 0:
				print('There was an error submitting the domain for scanning.')

			elif jsonResponse['response_code'] == -2:
				print('Report for {!r} is not ready yet. Please check the site\'s report.'.format(domainSani))

			else:
				print('Reading report for', domainSani)
			#permalink = "Full report: " + str(jsonResponse['permalink'])
			#scandate = "Last scanned time (-5 hours for EST time): " + str(jsonResponse['scan_date'])
			#positives = "Positive results: " + str(jsonResponse['positives']) + str("/") + str(jsonResponse['total'])
			#total = "Total number of scanning engines: " + str(jsonResponse['total'])

			#data = [domainSani, scandate, positives, permalink]
			#returnedData = '\n'.join(str(e) for e in data)
			print("Releasing Semaphore")
			semaphore.release()
			if int(jsonResponse['positives']) > 0:
				returnedData = domainSani + "\n[Virustotal](" + str(jsonResponse['permalink']) + ") says...potentially malicious!\n"
				return returnedData
			else:
				returnedData = domainSani + "\n[Virustotal](" + str(jsonResponse['permalink']) + ") says...not malicious!\n"
				return returnedData

		except ValueError:
			print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
			domainErrors.append(domainSani)

		except KeyError:
			print('There was an error when scanning {!s}. Adding domain to error list....'.format(domainSani))
			domainErrors.append(domainSani)
	elif r.status_code == 204:
		print('Received HTTP 204 response. You may have exceeded your API request quota or rate limit (for reporting).')

async def urlScanIO(domain):
	domainSani = re.sub('(^w{3}[3]?\.)|(^http[s]?\:\/\/)|(\/$)', '', domain)
	while (bool(re.search('(^w{3}[3]?\.)|(^http[s]?\:\/\/)|(\/$)', domainSani)))==True:
		domainSani = re.sub('(^w{3}[3]?\.)|(^http[s]?\:\/\/)|(\/$)', '', domainSani)
	url = 'https://urlscan.io/api/v1/search/?q=page.domain:' + domainSani
	r = requests.get(url)
	results = json.loads(r.text)
	try:
		l = results["results"][0]["result"]
		print(l)
		r1 = requests.get(l)
		v = json.loads(r1.text)
		m = v["verdicts"]["overall"]["malicious"]
		try:
			lastScanned = v["data"]["requests"][0]["response"]["response"]["headers"]["date"]
		except:
			lastScanned = v["data"]["requests"][0]["response"]["response"]["headers"]["Date"]
		ipaddress = v["data"]["requests"][0]["response"]["response"]["remoteIPAddress"]
		port = v["data"]["requests"][0]["response"]["response"]["remotePort"]
		country = v["data"]["requests"][0]["response"]["geoip"]["country"]
		region = v["data"]["requests"][0]["response"]["geoip"]["region"]
		city = v["data"]["requests"][0]["response"]["geoip"]["city"]
		print(str(lastScanned) + "\n" + str("Destination IP and port: ") + str(ipaddress) + str(":") + str(port) + "\n" + str(city) + ", " + str(region) + ", " + str(country) + "\n" + str("Verdict: ") + str(m))

		if str(m) == "False":
			return ("[urlscan.io](" + url + ") says...not malicious! \n" + str("IP/port: ") + str(ipaddress) + str(":") + str(port) + "\n" + str(city) + ", " + str(region) + ", " + str(country))
		if str(m) == "True":
			return ("[urlscan.io](" + url + ") says...potentially malicious! \n" + str("IP/port: ") + str(ipaddress) + str(":") + str(port) + "\n" + str(city) + ", " + str(region) + ", " + str(country))
	except:
		return ("No scan history on urlscan.io!")
		#some domains return results which only live ephemerally on the "https://urlscan.io/api/v1/search/?q=page.domain:" endpoint (ie. not retrievable after ~1 min.--reddit.com is one example.)
async def sucuriScanner(rawURL):
	s = time.perf_counter()
	domainSani = re.sub('(^w{3}[3]?\.)|(^http[s]?\:\/\/)|(\/$)', '', rawURL)
	while (bool(re.search('(^w{3}[3]?\.)|(^http[s]?\:\/\/)|(\/$)', domainSani)))==True:
		domainSani = re.sub('(^w{3}[3]?\.)|(^http[s]?\:\/\/)|(\/$)', '', domainSani)
		print(domainSani)
	link =str("https://sitecheck.sucuri.net/results/" + domainSani)
	asession = AsyncHTMLSession()
	wait_sess = await asession.get(link)
	await wait_sess.html.arender(timeout=60) #sleep=3 #race condition: tags is returned empty when the render function is not completed in time or before the find functions are executed; and findAll does not correctly parse the HTML it given, and therefore verdictSucuri(tags) and blacklistSucuri(tags) functions fail by returning the default values of [Verdict] and [Blacklist]; Solution: increase timeout
	full_html = wait_sess.html.html	
	soup = bs(full_html, features="html.parser")
	soup1 = bs(soup.prettify(), features="html.parser")
	tags = soup1.find_all("div", {"class": "box scan-header clearfix"})
	#print(tags)
	while len(tags) == 0:
		time.sleep(1)
		wait_sess = await asession.get(link)
		await wait_sess.html.arender(timeout=60)
		full_html = wait_sess.html.html	
		soup = bs(full_html, features="html.parser")
		soup1 = bs(soup.prettify(), features="html.parser")
		#print(str(soup1) + "chicken")
		tags = soup1.find_all("div", {"class": "box scan-header clearfix"})
		print(len(tags))

	replaced = await verdictSucuri(tags)
	replaced_bl = await blacklistSucuri(tags)

	await asession.close()
	elapsed = time.perf_counter() - s
	print("Sucuri scan time for " + str(rawURL) + str(": ") + str(elapsed) + " seconds.")
	return str("[Sucuri](" + link + ") says \" " + replaced + " \" and \" " + replaced_bl + "\"\n") 

async def verdictSucuri(tags):
	replaced = "[Verdict]"
	layer = tags[0].find("div", {"class": "inline"})
	print(len(tags))
	replaced = " ".join((re.sub('<[^>]*>', '', str(layer))).split())
	print("Verdict checked...")
	return replaced

async def blacklistSucuri(tags):
	replaced_bl = "[Blacklist]"
	layer1 = tags[0].find("div", {"class": "inline padding-left-35 notblacklisted"})
	if str(layer1) == "None":
		alt_layer1 = tags[0].find("div", {"class": "inline padding-left-35 hasblacklist"})
		replaced_bl = " ".join((re.sub('<[^>]*>', '', str(alt_layer1))).split())
	else:
		replaced_bl = " ".join((re.sub('<[^>]*>', '', str(layer1))).split())
	print("Blacklists checked...")
	return replaced_bl

#async def main(message):
#    a = await asyncio.gather(DomainScanner(message), sucuriScanner(message), urlScanIO(message))
#    return a

@client.event
async def on_ready():
	print('We have logged in as {0.user}'.format(client))
	try:
		with open('Magnify.png', 'rb') as fp:
			pfp = fp.read()
		#print(str(type(pfp)))
		await client.user.edit(avatar=pfp)
	except:
		pass
@client.event
async def on_message(message):
	if message.author == client.user:
		return

	if message.content.startswith('-inspire'):
		quote = get_quote()
		await message.channel.send(quote)

	if message.content.startswith('-help'):
		helpContent = str("```Hello, I'm your nifty URL scanning bot! Ever wondered if that link in the text channel were malicious?\n\nTo scan a link, ensure that it properly formatted. For example, to scan Yahoo's homepage, enter 'yahoo.com.' Invalid links include those with a TLD that is purely numeric (eg. yahoo.123)\n\n(Bonus: Feeling blue and need a bit of inspiration? Type '-inspire' for an inspirational quote.)```")
		await message.channel.send(helpContent)
		helpContent1 = str("```To get z random numbers between x and y, type in '-rng x y z'\n\nFor example, to return 8 random numbers between 5 and 20, type '-rng 5 20 8'```")
		await message.channel.send(helpContent1)

	if message.content.startswith('-rng'):
		try:
			start = int(message.content.split(" ")[1])
			end = int(message.content.split(" ")[2])
			try:
				setOfNumbers = int(message.content.split(" ")[3])
			except:
				setOfNumbers = 1
			modVal = end - start + 1
			#for x in range(setOfNumbers):
			#serial = int.from_bytes(os.urandom(10000), byteorder="big") #translates a random 10000 character hex string into their decimal unicode equivalents
			#	num = ((serial % modVal) + start)
			#	print(num)
			numbers = ", ".join([str(((int.from_bytes(os.urandom(100000), byteorder="big") % modVal) + start)) for z in range(setOfNumbers)])
			print(numbers)
			await message.channel.send("Your number is/numbers are: " + str(numbers))
			#Suppose for os.urandom(2), we produce the byte string b'S\xc5' with characters 'S' and "c5", and ord(b'S') = 83 and ord(b'\xc5') = 197
			#(83 * 256^1 + 197 * 256^0 = 21445) -> int.from_bytes(b'S\xc5', byteorder="big")
			#https://stackoverflow.com/questions/50509017/how-is-int-from-bytes-calculated
		except:
			await message.channel.send("Error!")
	if bool(re.search('(^w{3}[3]?\.)|(^http[s]?\:\/\/)', message.content)) or bool(re.search('.+(\.[A-Za-z]+)$', message.content))==True:
		scanresult2 = await sucuriScanner(str(message.content))
		scanresult3 = await urlScanIO(str(message.content))
		global mySemaphore
		scanresult = await DomainScanner(str(message.content), mySemaphore)
		embed = discord.Embed()
		embed.description = str(scanresult + scanresult2 + scanresult3)
		await message.channel.send(embed=embed)

client.run('DiscordAPIKey')
