#!/usr/bin/env python
'''
Mounts OSM traces of a logged in user as a read-only FUSE filesystem

Usage:
 osm_traces_fuse.py -o password=PASSWORD OSMLOGIN MOUNTPOINT

Example:
 mkdir /tmp/mytraces
 osm_traces_fuse.py -o password=mypass 'Joe Doe' /tmp/mytraces

Fstab entry:
 osm_traces_fuse.py#Joe\040Doe    /tmp/traces    fuse    user,noauto,ro,password=mypass

'''

import os
import re
import stat
import io
import argparse
import xml.etree.ElementTree as ET
import requests
import magic
import bz2
import gzip
import logging

from fuse import FUSE, Operations
from xml.etree.ElementTree import ParseError as PError
from time import mktime, strptime

_urllist = 'https://api.openstreetmap.org/api/0.6/user/gpx_files'
_urlget = 'https://api.openstreetmap.org/api/0.6/gpx/%s/data'


class OsmTraces(Operations):
    def __init__(self, user, password):
        self.user = user
        self.password = password
        r = requests.get(_urllist, auth=(self.user, self.password))
        try:
            tree = ET.fromstring(r.text)
        except PError:
            raise Exception('Error getting tracks: Probably a bad user/password combination')
        # self.track_dir is the main directory holding id and track data
        self.track_dir = dict()
        for _, gpx in enumerate(tree):
            self.track_dir['{0}_{1}'.format(gpx.get('timestamp'), gpx.get('id'))] = [gpx.get('id'), None]
        print('{0} tracks loaded'.format(_+1))

    def access(self, path, mode):
        return 0

    def getattr(self, path, fh=None):
        attr = {}
        if len(path.split('/')) < 3:
            attr['st_mode'] = stat.S_IFDIR | 0o755
            attr['st_size'] = 4096
        else:
            attr['st_mode'] = stat.S_IFREG | 0o400
            try:
                parent_dir = os.path.split(path)[0][1:]
                tid, data = self.track_dir[parent_dir]
                size = len(data.content)
                attr['st_size'] = size
            except:
                attr['st_size'] = 0
        try:
            times = mktime(strptime(path[1:], '%Y-%m-%dT%H:%M:%SZ'))
        except ValueError:
            times = 0
        attr['st_atime'] = times
        attr['st_ctime'] = times
        attr['st_mtime'] = times
        attr['st_gid'] = 0
        attr['st_nlink'] = 1
        return(attr)

    def readdir(self, path, fh):
        dirents = ['.', '..']
        if path in '/':
            for gpx in self.track_dir:
                dirents.extend([gpx])
        else:
            tid = self.track_dir[path[1:]][0]
            data = requests.get(_urlget % tid, auth=(self.user, self.password))
            logging.debug(data.headers['Content-Disposition'])
            filename = re.sub(r'.*filename="([^"]+?)".*', r'\1',
                              data.headers['Content-Disposition'])
            logging.debug('filename: {}'.format(filename))
            extension = re.match(r'([^.]+)(\..*)$', filename).groups()[1]
            self.track_dir[path[1:]][1] = data
            detected_type = magic.detect_from_content(data.content).mime_type
            type2fun = {'application/x-bzip2': bz2.decompress,
                        'application/x-gzip': gzip.decompress,
                        'text/xml': bytes,
                        'text/plain': bytes}
            conv_fun = type2fun.get(detected_type, None)
            if conv_fun:
                timedate_data = re.search(b'<time>([^T]+)T([^:]+:[^:]+):',
                                          type2fun[detected_type](data.content))
                date_data = timedate_data.group(1)
                time_data = timedate_data.group(2)
            else:
                time_data = b'notime'
            dirents.append('{0}_{1}_{2}{3}'.format(tid,
                                                   date_data.decode('ascii'),
                                                   time_data.decode('ascii'),
                                                   extension))
        for r in dirents:
            yield r

    def open(self, path, flags):
        return 0

    def read(self, path, length, offset, fh):
        tstamp = path.split('/')[1]
        if tstamp not in self.track_dir:
            return
        bio = io.BytesIO(self.track_dir[tstamp][1].content)
        bio.seek(offset)
        return bio.read(length)

    def flush(self, path, fh):
        return


def main():
    parser = argparse.ArgumentParser(description='Mount OSM traces as FUSE Filesystem')
    parser.add_argument('user', nargs=1, help='OSM username')
    parser.add_argument('mountpoint', nargs=1, help='Mountpoint')
    parser.add_argument('-o', nargs=1, dest='options', help='Mount options (currently only password is parsed and required)')
    parser.add_argument('-d', dest='debug', action='store_true', default=False, help='Debug mode')
    parser.add_argument('-f', dest='foreground', action='store_true', default=False, help='Run in foreground')

    args = parser.parse_args()
    options = args.options[0].split(',')
    if not [x for x in options if re.match('password=.', x)]:
        raise Exception('Password is mandatory!')
    password = [x.split('=')[1] for x in options if x.startswith('password=')][0]
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    FUSE(OsmTraces(args.user[0], password), args.mountpoint[0], nothreads=True, foreground=args.foreground,
         debug=args.debug)


if __name__ == '__main__':
    main()
