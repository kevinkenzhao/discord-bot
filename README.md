# discord-bot

The Discord bot was birthed from the desire for addressing occasional, miscellaneous functions in a private Discord server. What began as a URL checker was quickly augmented to provide inspirational quotes and a random number generator.

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

The script has been verified as working under Python 3.7.9. However, I suspect most versions of Python 3 will work without issue. If you have downloaded a version of Python >=3.4 via python.org, then pip is already installed. Otherwise, you will need to install pip separately. Next, download the requirements.txt file provided in this repository. Finally, run "python -m pip install -r Path\to\requirements.txt," where "python" is an environmental variable pointing to the Python executable (eg. C:\Python37\python.exe)--you may need to restart your computer after newly installing Python or creating the variable in order for changes to take effect.

## URL Scanning

Our bot gathers, parses, and presents the verdict and other descriptors about the URL(s) in question from three website scanning services: VirusTotal, Sucuri SiteCheck, and urlscan.io. We accomplish this by submitting standard POST requests to an API endpoint and parsing the returned json object or through web scraping. Because the Sucuri SiteCheck website is dynamic (i.e. the Javascript within must be executed to produce the desired HTML data), the code launches an instance of Chromium in the background for headless rendering. Unfortunately this approach can be resource-intensive if the host instance has limited computing or network resources (eg. Micro instance on AWS) and URLs are submitted in rapid succession.

### Considerations for VirusTotal Scanning
----
Because the VirusTotal public (ie. free) API imposes a limit of four requests/minute, we design a scheduling mechanism that is configured to asynchronously process up to two URL scan requests and synchronously sleep/resume when the program detects that all four requests have been temporarily depleted. We limit the Semaphore value to 2 to ensure that results are returned to the Discord chat in a timely manner. Without a Semaphore, it is possible that provided a slew of 10 URL scan requests, the program would return the results of the first sometime after five minutes.


### Warning: Sucuri SiteCheck Usage

Using the Sucuri SiteCheck (sitecheck.sucuri.net) feature in the manner described above may constitute a violation of Sucuri's Terms of Service:
```
You shall not attempt or engage in potentially harmful acts that are directed against the Sites or Service including, without limitation, the following...using manual or automated software, devices, scripts, robots, or other means or processes to access, “scrape,” “crawl,” or “spider” any pages contained in the Sites"
```

## Random Number Generation

Our bot leverages the os.urandom(x) function from the os library to gather 10000 pseudorandom bytes (presented in big-endian format) and convert each of them into integers via the ord() function--the resulting numeric string will be in BASE 256. The BASE 10 equivalent of the aforementioned string will be the "seed" value for our function.
