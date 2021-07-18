# discord-bot

The Discord bot was birthed from the desire for addressing occasional, miscellaneous functions in a private Discord server. What began as a URL checker was quickly augmented to provide inspirational quotes and a random number generator. The goal of this exercise is to grapple with API querying/response(s), dynamic webpage scraping and parsing, and scheduling in an asynchronous programming scenario.

By calling ```client.run('api_key')``` in the last line of the script, we have instructed the bot to run an [indefinite event loop until the logout() coroutine is called](https://discordpy.readthedocs.io/en/latest/api.html#discord.Client.run).

For security reasons, the VirusTotal and Discord API keys have been redacted. If you wish to use the script, please ensure that both are supplied.

## Bot Avatar

The script attempts to search for and upload an avatar to Discord during execution. By default, the script will attempt to look for "Magnify.png" in the current directory, but this can be tailored as needed.
```
try:
	with open('Magnify.png', 'rb') as fp:
		pfp = fp.read()
	await client.user.edit(avatar=pfp)
except:
	pass
```
The recommended icon resolution is 128 pixels * 128 pixels, but Magnify.png (513 pixels * 512 pixels) can be uploaded without issue.

## Prerequisites

The script has been verified working under Python 3.7.9 and 3.8.7, though I suspect other versions of Python 3 are compatible too.

### Windows

If you have downloaded a Python >=3.4 installer via python.org, you will be presented with an option to install pip. Otherwise, you will need to install pip separately. Next, download the requirements.txt file provided in this repository. Finally, run "python -m pip install -r Path\to\requirements.txt," where "python" is an environmental variable pointing to the Python executable (eg. C:\Python37\python.exe)--you may need to restart your computer after newly installing Python or creating the variable in order for changes to take effect.

If performed correctly, the libraries specified in requirements.txt should be downloaded as seen below:

![alt text](https://github.com/kevinkenzhao/discord-bot/blob/main/bulk_pip_install.PNG?raw=true)

Example of first run using Python 3.8.7 as seen from the client and server ends:

![alt text](https://github.com/kevinkenzhao/discord-bot/blob/main/first_run_client.PNG?raw=true)

![alt text](https://github.com/kevinkenzhao/discord-bot/blob/main/first_run_server.PNG?raw=true)

### Docker (Alpine Linux)

To allow for greatest cross-platform compatibility, we configured the bot to run within a ``python:3.8.0-alpine`` Docker image. (Note: ensure Docker is installed on the machine before proceeding.)

To kickstart the deployment process, download the entire repository and extract it:
1. ``curl https://codeload.github.com/kevinkenzhao/discord-bot/zip/refs/heads/main -O discord-bot``
2. ``sudo apt install unzip && unzip discord-bot``

Next, let us build a custom Docker image from the Dockerfile (note: this action assume the current working directory ``discord-bot``): ``docker build --no-cache -t discord-bot/url-scan:v0 .``

Verify that the container has successfully spawned:

![alt text](https://github.com/kevinkenzhao/discord-bot/blob/main/bot-docker-list-container.PNG?raw=true)



## Options Summary

- standalone submission of valid URL (default)
- ``-inspire``: returns an inspirational quote
- ``-help``: returns the full list of functions and their usage
- ``-rng x y z``: returns z random numbers between x and y

## URL Scanning

Our bot considers any string that starts with:
* www.
* http://
or ends with a strictly alphabetic TLD as a valid URL (eg. sampledomain.123 would be invalid).

Our bot gathers, parses, and presents the verdict and other descriptors about the URL(s) in question from three website scanning services: VirusTotal, Sucuri SiteCheck, and urlscan.io. We accomplish this by submitting standard POST requests to an API endpoint and parsing the returned json object or through web scraping. Because the Sucuri SiteCheck website is dynamic (i.e. the Javascript within must be executed to produce the desired HTML data), the code launches an instance of Chromium in the background for headless rendering. Unfortunately this approach can be resource-intensive if the host instance has limited computing or network resources (eg. Micro instance on AWS) and URLs are submitted in rapid succession. One possible mitigation to this DoS vulnerability, is to limit the number of asynchronous Chromium instances to a manageable number like 5 with a Semaphore.

Note: Sucuri SiteCheck and urlscan.io will return results on a "best effort" basis. That is to say, they may occasionally return unexpected results to valid sites. For example, querying "reddit.com" on Sucuri SiteCheck results in a "429 Too Many Requests." This often occurs when a site automatically redirects to its HTTPS version if the HTTP version is visited.

### Considerations for VirusTotal Scanning

Because the VirusTotal public (ie. free) API imposes a limit of four requests/minute, we design a scheduling mechanism that is configured to asynchronously process up to two URL scan requests at a time using a Semaphore and synchronously halts the program for a duration of (60 - masterTime), where masterTime is Δ(time at count=4)-(time at count=0). Although we might assume that the API quota has been reset if masterTime >= 60s at time count=0, the program errs on the side of caution and halts for 20 seconds. We limit the Semaphore value to 2 to ensure that results are returned to the Discord chat in a timely manner. Without a Semaphore, it is possible that provided a slew of 10 URL scan requests, the program would return the results of the first sometime after five minutes.


#### Warning: Sucuri SiteCheck Usage

*Using the Sucuri SiteCheck (sitecheck.sucuri.net) feature in the manner described above may constitute a violation of Sucuri's Terms of Service:*
```
You shall not attempt or engage in potentially harmful acts that are directed against the Sites or Service including, without limitation, the following...using manual or automated software, devices, scripts, robots, or other means or processes to access, “scrape,” “crawl,” or “spider” any pages contained in the Sites...
```

## Inspirational Quote Generation

Inspirational quotes are queried from the free https://zenquotes.io/api/random endpoint. The returned json response is parsed for "quote" and "author" fields, which are both returned to the Discord chat.

## Random Number Generation

Our bot leverages the os.urandom(x) function from the os library to gather 10000 pseudorandom bytes (presented in big-endian format) and convert each of them into integers via the ord() function—the resulting numeric string will be in BASE 256. The BASE 10 equivalent of the aforementioned string will be the "seed" value for our function.

Example:

1. Suppose for os.urandom(2), we produce the byte string b'S\xc5' with characters 'S' and "c5" 
2. ord(b'S') = 83 and ord(b'\xc5') = 197.
3. Because the byte order is big endian, we have (83 * 256^1 + 197 * 256^0 = 21445) which is the same value derived using ```int.from_bytes(b'S\xc5', byteorder="big")```
4. Conversely, ```int.from_bytes(b'\x00\x10', byteorder='little')``` would yield (197 * 256^1 + 83 * 256^0 = 50515).
