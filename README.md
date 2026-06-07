# http2checker
Just a Python vibe coding experiment to check an URL for HTTP, HTTPS, HTTP/2.0....

## Usage:

http2checker.py [-h] [-f FILE] [-k] [-v] [-o OUTPUT] [domain]

HTTP2Checker: DNS, IP, SSL, Server, Title and CSV export

positional arguments:
  domain                A single URL to check

options:
  -h, --help            	show this help message and exit
  -f FILE, --file FILE  	List of URLs to check, one per line
  -k, --insecure        	Ignore SSL error
  -v, --verbose         	Show exception details for debugging
  -o OUTPUT, --output OUTPUT    Export on CSV in file 'OUTPUT'
