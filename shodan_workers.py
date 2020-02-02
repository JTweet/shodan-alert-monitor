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
import multiprocessing
import queue
import json

# Import 3rd party libraries
from shodan import Shodan, APIError

def dump(obj):
    for attr in dir(obj):
        if hasattr(obj, attr):
            print("obj.%s = %s" % (attr, getattr(obj, attr)))

class Configuration:
    def __init__(self, configuration_file):
        self.configuration = json.load(configuration_file)
        configuration_file.close()

    def get_api_key(self):
        return self.configuration.get('api_key')

    def get_collectors(self):
        return self.configuration.get('collectors')

class ServiceController:
    """ Class to manage the service
    """
    def __init__(self, configuration_file):
        self.configuration = Configuration(configuration_file)
        configuration_file.close()
        self.collectors = [ ]
        for collector in self.configuration.get_collectors():
            self.collectors.append(CollectorController(self.configuration.get_api_key(), collector.get('aid'), collector.get('log')))

    def start(self):
        for c in self.collectors:
            c.start()

    def stop(self):
        for c in self.collectors:
            c.shutdown()


class CollectorController:
    """ Class to manage a single collector
    """

    def __init__(self, api_key, aid, log_path):
        self.api_key = api_key
        self.aid = aid
        self.log_path = log_path
        self.out_queue = multiprocessing.Queue()
        self.writer = WriterWorker(
            out_queue=self.out_queue, filename=self.get_log_name())
        self.stream = StreamWorker(
            out_queue=self.out_queue, api_key=self.api_key, aid=self.aid)

    def get_log_name(self):
        return self.log_path

    def start(self):
        self.writer.start()
        self.stream.start()

    def stop_writer(self):
        self.writer.join()
        if self.writer.is_alive():
            self.writer.terminate()

    def stop_stream(self):
        self.stream.join()
        if self.stream.is_alive():
            self.stream.terminate()

    def restart_writer(self):
        self.stop_writer()
        self.writer = WriterWorker(
            out_queue=self.out_queue, filename=self.get_log_name())
        self.writer.start()

    def restart_stream(self):
        s = streamworker(out_queue=self.out_queue, api_key=self.api_key)
        s.start()
        time.sleep(0.5)
        self.stop_stream()
        self.stream = s

    def shutdown(self):
        self.stop_stream()
        while not self.out_queue.empty():
            time.sleep(1)

        self.stop_writer()


class StreamWorker(multiprocessing.Process):
    """ A worker to retreive data from the Shodan stream.
    """

    def __init__(self, out_queue, api_key, aid):
        super(StreamWorker, self).__init__()
        self.out_queue = out_queue
        self.api_key = api_key
        self.aid = aid
        self.terminate = multiprocessing.Event()

    def run(self):
        api = Shodan(self.api_key)

        while not self.terminate.is_set():
            try:
                for banner in api.stream.alert(aid=self.aid):
                # for banner in api.stream.banners():
                    self.out_queue.put(banner)
            except APIError:
                continue

    def join(self, timeout=1):
        self.terminate.set()
        super(StreamWorker, self).join(timeout)
        sys.exit()


class WriterWorker(multiprocessing.Process):
    """ A worker to log data from the Shodan stream to disk
    """

    def __init__(self, out_queue, filename):
        super(WriterWorker, self).__init__()
        self.out_queue = out_queue
        self.fh = open(filename, 'a')
        self.terminate = multiprocessing.Event()

    def run(self):
        while not self.terminate.is_set():
            try:
                banner = self.out_queue.get(True, 0.5)
                self.fh.write(json.dumps(banner) + '\n')
            except queue.Empty:
                continue

        self.fh.close()

    def join(self, timeout=3):
        self.terminate.set()
        super(WriterWorker, self).join(timeout)
        sys.exit()
