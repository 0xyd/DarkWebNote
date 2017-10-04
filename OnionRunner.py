from stem.control import Controller
from stem import Signal
from threading import Timer
from threading import Event

import json
import os
import random
import subprocess
import sys
import time

onions = []
session_onions = []

# Event object is used to coordinate two threads that will be executing
identity_lock = Event()
identity_lock.set()

