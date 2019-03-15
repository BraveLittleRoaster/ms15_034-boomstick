Requirements:

Python >= 3.6

Install requirements with: 

`pip3 install -r requirements.txt`

Usage example:

`python3 ms15_boomstick.py -u http://targeturl.com/ -c -d`

Args:

```
optional arguments:
  -h, --help            show this help message and exit
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        Log level to use: debug, info, warn, err
  -o LOG_LOCATION, --log-dir LOG_LOCATION
                        Specify the location for the log file to be saved.
  -f INPUT_FILE, --file INPUT_FILE
                        Specify a list of URLs to scan or DoS.
  -d, --dos             Execute a DoS attack against the target(s).
  -c, --check           Check for vulnerable hosts.
  -u URL, --url URL     Execute a scan or DoS on a single host.

```