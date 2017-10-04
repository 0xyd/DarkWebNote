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

from settings import HASH_PWD, PORT

onions = []
session_onions = []

# Event object is used to coordinate two threads that will be executing
identity_lock = Event()
identity_lock.set()

def get_onion_list():
    '''get_onion_list
    :description:
        Get the onions from the file
    :return:
        The list of onions
    '''
    onion_names_list = 'onion_master_list.txt'
    if os.path.exists(onion_names_list):
        onions = open(onion_names_list, 'r').readlines()
        print('There are %d onions for scanning' % len(onions))
        return onions
    else:
        print('Download the onion list before running.')
        sys.exit()
        return []

def store_onion(onion):
    '''store_onion
    :description:
        Record the new onion in the list that we would like to scan later.
    :params:
        onion:
        a hidden service we would like to scan later
    '''
    onion_names_list = 'onion_master_list.txt'
    onion_record = open('onion_master_list.txt', 'a')
    onion.write('%s\n' % onion)

def run_onionscan(onion):
    '''run_scanning
    :description:
        Run orion scanning in children process. The process will scan onion for 5 minutes.
    :params:
        onion:
        a hidden sevice to be scanned.

    '''

    print('Start Orionscanning on %s' % onion)
    
    process = subprocess.Popen(
        ["orionscan", "webport=0", "--jsonReport", "--simpleReport=false", onion],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    process_timer = Timer(300, handle_timeout, args=[process, onion])
    process_timer.start()

    stdout = process.communicate()[0]

    # Kill the timer after we recevied value
    if process_timer.is_alive():
        process_timer.cancel()
        return stdout

    print('The scan process timed out!')
    return None

def handle_timeout(process, onion):
    '''handle_timeout
    :decription:
        Handle the timeout of the onionscan process. 
        This might cause by unstable network connection or
        the hidden service is no longer be connected.

    :params:
        process:
        The onionscan process which exceed the running time limit

        onion:
        The hidden service seems
    '''

    global session_onions
    global identity_lock

    # Halt the main thread while we grab a new identity
    identity_lock.clear()

    try:
        process.kill()
        print("Kill the onionscan process")
    except:
        pass

    with Controller.from_port(port=PORT) as torcontrol:

        torcontrol.authenticate(HASH_PWD)

        # Send the signal for a new identity
        torcontrol.signal(Signal.NEWNYM)

        time.sleep(torcontrol.get_newnym_wait())
        print('Swithed TOR identities')

    session_onions.append(onion)
    random.shuffle(session_onions)

    # Resume the main thread
    identity_lock.set()

def process_results(onion, json_response):
	'''process_results
	:description:
		Process the json result made by onionscan
	:params:
		onion: 
		The hidden server

	json_response:
		The output json data of onionscan
	'''

	global onions
	global session_onions

	if not os.path.exists('onionscan_results'):
		os.mkdir("onionscan_results")

	with open('%s/%s.json' % ('onionscan_results', onion), 'wb') as f:
		f.write(json_response)

	scan_result = '%s' % json_response.decode('utf8')
	scan_result = json.loads(scan_result)

	if scan_result['identifierReport']['linkedOnions'] is not None:
		add_new_onions(scan_result['identifierReport']['linkedOnions'])

	if scan_result['identifierReport']['relatedOnionDomains'] is not None:
		add_new_onions(scan_result['identifierReport']['relatedOnionDomains'])

	if scan_result['identifierReport']['relatedOnionServices'] is not None:
		add_new_onions(scan_result['identifierReport']['relatedOnionServices'])

def add_new_onions(new_onion_list):
    '''add_new_onions
    :description:
        Add new onions to the scan list

    :params:
        new_onion_list:
    '''
    global onions
    global session_onions

    for linked_onion in new_onion_list:

        if linked_onion not in onions and linked_onion.endswith('.onion'):
            print('[++] Discovered new .onion: %s' % linked_onion)
            onions.append(linked_onion)
            session_onions.append(linked_onion)
            random.shuffle(session_onions)
            store_onion(linked)

def main():
    onions = get_onion_list()
    random.shuffle(onions)
    session_onions = list(onions)

    count = 0

    while count < len(onions):

        identity_lock.wait()
        print("[*] Running %d of %d" % (count, len(onions)))
        onion = session_onions.pop()

        if os.path.exists("onionscan_results/%s.json" % onion):
            print("[!] Already retrieved %s. Skipping" % onion)
            count += 1
            continue
        result = run_onionscan(onion)

        if result is not None:
            if len(result):
                process_results(onion, result)
                count += 1


if __name__ == '__main__':
    main()

