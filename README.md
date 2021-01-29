# discord-bot

The Discord bot was birthed from the desire for addressing occasional, miscellaneous functions in a private Discord server. What began as a URL checker was quickly augmented to provide inspirational quotes and a random number generator.

## Prerequisites

The script has been verified to run under Python 3.7.9 without issue. However, I suspect most versions of Python 3 will work without issue.


## URL Scanning

Our bot gathers, parses, and presents the verdict and other descriptors about the URL(s) in question from three website scanning services: VirusTotal, Sucuri SiteCheck, and urlscan.io. We accomplish this by submitting standard POST requests to an API endpoint and parsing the returned json object or through web scraping. Because the Sucuri SiteCheck website is dynamic (i.e. the Javascript within must be executed to produce the desired HTML data), the code launches an instance of Chromium in the background for headless rendering. Unfortunately this approach can be resource-intensive if the host instance has limited resources (eg. Micro instance on AWS) and/or URLs are submitted in rapid succession.

### Considerations for VirusTotal Scanning
----
Because the VirusTotal public (ie. free) API imposes a limit of four requests/minute, we design a scheduling mechanism that is configured to asynchronously process up to two URL scan requests and synchronously sleep/resume when the program detects that all four requests have been temporarily depleted. We limit the Semaphore value to 2 to ensure that results are returned to the Discord chat in a timely manner. Without a Semaphore, it is possible that provided a slew of 10 URL scan requests, the program would return the results of the first sometime after five minutes. 

## Random Number Generation

Our bot leverages the os.urandom(x) function from the os library to gather 10000 pseudorandom bytes (presented in big-endian format) and convert each of them into integers via the ord() function--the resulting numeric string will be in BASE 256. The BASE 10 equivalent of the aforementioned string will be the "seed" value for our function.
