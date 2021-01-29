# discord-bot

The Discord bot was birthed from the desire for addressing occasional, miscellaneous functions in a private Discord server. What began as a URL checker was quickly augmented to provide inspirational quotes and a random number generator.

## Prerequisites

The script has been verified to run under Python 3.7.9 without issue. However, I suspect most versions of Python 3 will work without issue.


## URL Scanning

Our bot gathers, parses, and presents the verdict and other descriptors about the URL(s) in question from three website scanning services: VirusTotal, Sucuri SiteCheck, and urlscan.io. We accomplish this by submitting standard POST requests to an API endpoint and parsing the returned json object or through web scraping. Because the Sucuri SiteCheck website is dynamic (i.e. the Javascript within must be executed to produce the desired HTML data), the code launches an instance of Chromium in the background for headless rendering. Unfortunately this approach can be resource-intensive if the host instance has limited resources (eg. Micro instance on AWS) and/or URLs are submitted in rapid succession.

## Random Number Generation

Our bot leverages the os.urandom(x) function from the os library to gather 10000 pseudorandom bytes (presented in big-endian format) and convert each of them into integers via the ord() function--the resulting numeric string will be in BASE 256. The BASE 10 equivalent of the aforementioned string will be the "seed" value for our function.
