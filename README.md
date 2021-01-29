# discord-bot

The Discord bot was birthed from the desire for addressing occasional, miscellaneous functions in a private Discord server. What began as a URL checker was quickly augmented to provide inspirational quotes and a random number generator.

## Prerequisites

The script has been verified to run under Python 3.7.9 without issue. However, I suspect most versions of Python 3 will work without issue.


## URL Scanning

Our bot gathers, parses, and presents the verdict and other descriptors about the URL(s) in question from three website scanning services: VirusTotal, Sucuri SiteCheck, and urlscan.io. We accomplish this by submitting standard POST requests to an API endpoint and parsing the returned json object or through web scraping. Because the Sucuri SiteCheck website is dynamic (i.e. the Javascript within must be executed to produce the desired HTML data), the code launches an instance of Chromium in the background for headless rendering. Unfortunately this approach can be resource-intensive if the host instance has limited resources (eg. Micro instance on AWS) and/or URLs are submitted in rapid succession.
