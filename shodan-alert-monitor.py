#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

# shodan-alert-monitor
# Copyright (C) 2020, Oliver "JTweet" Springer
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import time
import argparse
import signal
import shodan_workers


def dump(obj):
    for attr in dir(obj):
        if hasattr(obj, attr):
            print("obj.%s = %s" % (attr, getattr(obj, attr)))

def main(configuration_file):
    def shutdown_handler(*args):
        c.stop()
        print("SIGINT caught.")
        sys.exit()

    signal.signal(signal.SIGINT, shutdown_handler)
    c = shodan_workers.ServiceController(configuration_file)
    c.start()
    while True:
        time.sleep(5)

ap = argparse.ArgumentParser(
    description='A tool to log shodan alerts to a file. Output is provided as JSON')
ap.add_argument('configuration', type=argparse.FileType('r'))
ap.add_argument('--verbose', '-v', required=False, default=False,
              help='Tee debug output to STDOUT', action='store_true')

args = ap.parse_args()

main(args.configuration)
