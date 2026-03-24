# app/common/banner.py

from pyfiglet import Figlet
from colorama import Fore, Style, init
from datetime import datetime
import platform

init(autoreset=True)

APP_VERSION = "2.0.0"
ENVIRONMENT = "PROD"

def show_banner():

    f = Figlet(font="slant")
    banner = f.renderText("OCTOPUS")

    print(Fore.MAGENTA + Style.BRIGHT + banner)
    print(Fore.CYAN + "=" * 70)
    print(Fore.YELLOW + f"  Version     : {APP_VERSION}")
    print(Fore.YELLOW + f"  Environment : {ENVIRONMENT}")
    print(Fore.YELLOW + f"  Python      : {platform.python_version()}")
    print(Fore.YELLOW + f"  Time        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.CYAN + "=" * 70)
