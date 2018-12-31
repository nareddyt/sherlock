"""
Sherlock: Find Usernames Across Social Networks Module

This module contains the main logic to search for usernames at social
networks.
"""

import requests
from concurrent.futures import ThreadPoolExecutor
from requests_futures.sessions import FuturesSession
import json
import os
import re
import csv
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import platform
from torrequest import TorRequest
import asyncio
import aiohttp
import time

aiohttp.ClientSession()

module_name = "Sherlock: Find Usernames Across Social Networks"
__version__ = "2018.12.30"


# TODO: fix tumblr


def write_to_file(url, fname):
    with open(fname, "a") as f:
        f.write(url + "\n")


def print_error(err, errstr, var, debug=False):
    if debug:
        print(f"\033[37;1m[\033[91;1m-\033[37;1m]\033[91;1m {errstr}\033[93;1m {err}")
    else:
        print(f"\033[37;1m[\033[91;1m-\033[37;1m]\033[91;1m {errstr}\033[93;1m {var}")


async def sherlock(username, verbose=False, tor=False, unique_tor=False):
    """Run Sherlock Analysis.

    Checks for existence of username on various social media sites.

    Keyword Arguments:
    username               -- String indicating username that report
                              should be created against.
    verbose                -- Boolean indicating whether to give verbose output.
    tor                    -- Boolean indicating whether to use a tor circuit for the requests.
    unique_tor             -- Boolean indicating whether to use a new tor circuit for each request.

    Return Value:
    Dictionary containing results from report.  Key of dictionary is the name
    of the social network site, and the value is another dictionary with
    the following keys:
        url_main:      URL of main site.
        url_user:      URL of user on site (if account exists).
        exists:        String indicating results of test for account existence.
        http_status:   HTTP status code of query which checked for existence on
                       site.
        response_text: Text that came back from request.  May be None if
                       there was an HTTP error when checking for existence.
    """
    fname = username + ".txt"

    if os.path.isfile(fname):
        os.remove(fname)
        print(
            "\033[1;92m[\033[0m\033[1;77m*\033[0m\033[1;92m] Removing previous file:\033[1;37m {}\033[0m".format(fname))

    print(
        "\033[1;92m[\033[0m\033[1;77m*\033[0m\033[1;92m] Checking username\033[0m\033[1;37m {}\033[0m\033[1;92m on: \033[0m".format(
            username))

    # A user agent is needed because some sites don't
    # return the correct information since they think that
    # we are bots
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0'
    }

    # Load the data
    with open("data.json", "r", encoding="utf-8") as raw:
        data = json.load(raw)

    # Allow 1 thread for each external service, so `len(data)` threads total
    executor = ThreadPoolExecutor(max_workers=len(data))

    # Create session based on request methodology
    underlying_session = requests.session()
    underlying_request = requests.Request()
    if tor or unique_tor:
        underlying_request = TorRequest()
        underlying_session = underlying_request.session()

    # Create multi-threaded session for all requests
    session = aiohttp.ClientSession()

    # Results from analysis of all sites
    results_total = {}

    start_time = time.time()

    # First create futures for all requests. This allows for the requests to run in parallel
    for social_network, net_info in data.items():

        # Results from analysis of this specific site
        results_site = {}

        # Record URL of main site
        results_site['url_main'] = net_info.get("urlMain")

        # Don't make request if username is invalid for the site
        exists = None
        regex_check = net_info.get("regexCheck")
        if regex_check and re.search(regex_check, username) is None:
            # No need to do the check at the site: this user name is not allowed.
            print(
                "\033[37;1m[\033[91;1m-\033[37;1m]\033[92;1m {}:\033[93;1m Illegal Username Format For This Site!".format(
                    social_network))
            exists = "illegal"
        else:
            # URL of user on site (if it exists)
            url = net_info["url"].format(username)
            results_site["url_user"] = url

            # Get the expected error type
            error_type = net_info["errorType"]

            # Default data in case there are any failures in doing a request.
            http_status = "?"
            response_text = ""

            async with session.get('http://httpbin.org/get') as resp:
                r = resp

                http_status = r.status
                response_text = await r.text()

                if error_type == "message":
                    error = net_info.get("errorMsg")
                    # Checks if the error message is in the HTML
                    if not error in response_text:
                        print("\033[37;1m[\033[92;1m+\033[37;1m]\033[92;1m {}:\033[0m".format(social_network), url)
                        write_to_file(url, fname)
                        exists = "yes"
                    else:
                        print("\033[37;1m[\033[91;1m-\033[37;1m]\033[92;1m {}:\033[93;1m Not Found!".format(social_network))
                        exists = "no"

                elif error_type == "status_code":
                    # Checks if the status code of the response is 404
                    if not http_status == 404:
                        print("\033[37;1m[\033[92;1m+\033[37;1m]\033[92;1m {}:\033[0m".format(social_network), url)
                        write_to_file(url, fname)
                        exists = "yes"
                    else:
                        print("\033[37;1m[\033[91;1m-\033[37;1m]\033[92;1m {}:\033[93;1m Not Found!".format(social_network))
                        exists = "no"

                elif error_type == "response_url":
                    error = net_info.get("errorUrl")
                    # Checks if the redirect url is the same as the one defined in data.json
                    if error != r.url:
                        print("\033[37;1m[\033[92;1m+\033[37;1m]\033[92;1m {}:\033[0m".format(social_network), url)
                        write_to_file(url, fname)
                        exists = "yes"
                    else:
                        print("\033[37;1m[\033[91;1m-\033[37;1m]\033[92;1m {}:\033[93;1m Not Found!".format(social_network))
                        exists = "no"

                elif error_type == "":
                    print("\033[37;1m[\033[91;1m-\033[37;1m]\033[92;1m {}:\033[93;1m Error!".format(social_network))
                    exists = "error"

        # Save exists flag
        results_site['exists'] = exists

        # Save results from request
        results_site['http_status'] = http_status
        results_site['response_text'] = response_text

        # Add this site's results into final dictionary with all of the other results.
        results_total[social_network] = results_site

    print("\033[1;92m[\033[0m\033[1;77m*\033[0m\033[1;92m] Saved: \033[37;1m{}\033[0m".format(username + ".txt"))

    await session.close()
    end_time = time.time()
    print("Elapsed time was %g seconds" % (end_time - start_time))

    return results_total


async def main():
    version_string = f"%(prog)s {__version__}\n" + \
                     f"{requests.__description__}:  {requests.__version__}\n" + \
                     f"Python:  {platform.python_version()}"

    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                            description=f"{module_name} (Version {__version__})"
                            )
    parser.add_argument("--version",
                        action="version", version=version_string,
                        help="Display version information and dependencies."
                        )
    parser.add_argument("--verbose", "-v", "-d", "--debug",
                        action="store_true", dest="verbose", default=False,
                        help="Display extra debugging information."
                        )
    parser.add_argument("--quiet", "-q",
                        action="store_false", dest="verbose",
                        help="Disable debugging information (Default Option)."
                        )
    parser.add_argument("--tor", "-t",
                        action="store_true", dest="tor", default=False,
                        help="Make requests over TOR; increases runtime; requires TOR to be installed and in system path.")
    parser.add_argument("--unique-tor", "-u",
                        action="store_true", dest="unique_tor", default=False,
                        help="Make requests over TOR with new TOR circuit after each request; increases runtime; requires TOR to be installed and in system path.")
    parser.add_argument("--csv",
                        action="store_true", dest="csv", default=False,
                        help="Create Comma-Separated Values (CSV) File."
                        )
    parser.add_argument("username",
                        nargs='+', metavar='USERNAMES',
                        action="store",
                        help="One or more usernames to check with social networks."
                        )

    args = parser.parse_args()

    # Banner
    print(
        """\033[37;1m                                              .\"\"\"-.
\033[37;1m                                             /      \\
\033[37;1m ____  _               _            _        |  _..--'-.
\033[37;1m/ ___|| |__   ___ _ __| | ___   ___| |__    >.`__.-\"\"\;\"`
\033[37;1m\___ \| '_ \ / _ \ '__| |/ _ \ / __| |/ /   / /(     ^\\
\033[37;1m ___) | | | |  __/ |  | | (_) | (__|   <    '-`)     =|-.
\033[37;1m|____/|_| |_|\___|_|  |_|\___/ \___|_|\_\    /`--.'--'   \ .-.
\033[37;1m                                           .'`-._ `.\    | J /
\033[37;1m                                          /      `--.|   \__/\033[0m""")

    if args.tor or args.unique_tor:
        print(
            "Warning: some websites might refuse connecting over TOR, so note that using this option might increase connection errors.")

    # Run report on all specified users.
    for username in args.username:
        print()
        results = await sherlock(username, verbose=args.verbose, tor=args.tor, unique_tor=args.unique_tor)

        if args.csv == True:
            with open(username + ".csv", "w", newline='') as csv_report:
                writer = csv.writer(csv_report)
                writer.writerow(['username',
                                 'name',
                                 'url_main',
                                 'url_user',
                                 'exists',
                                 'http_status'
                                 ]
                                )
                for site in results:
                    writer.writerow([username,
                                     site,
                                     results[site]['url_main'],
                                     results[site]['url_user'],
                                     results[site]['exists'],
                                     results[site]['http_status']
                                     ]
                                    )


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
