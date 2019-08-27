

import os,sys
sys.path.append('..')
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from core import ser_main

if __name__ == "__main__":
    ser_main.ArvgHandler()



