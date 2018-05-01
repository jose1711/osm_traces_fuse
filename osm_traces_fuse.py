#!/usr/bin/env python
'''
Mounts OSM traces of a logged in user
as a read-only FUSE filesystem

Usage:
 osm_traces_fuse.py -p PASSWORD OSMLOGIN MOUNTPOINT

Example:
 mkdir /tmp/mytraces
 osm_traces_fuse.py -p mypass 'Joe Doe' /tmp/mytraces

'''

import os
import re
import stat
import io
import argparse
import xml.etree.ElementTree as ET
import requests

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
        for _, gpx in enumerate(tree.getchildren()):
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
                attr['st_size'] = int(os.path.split(path)[-1].split('.')[0])
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
        attr['st_uid'] = 1000
        return(attr)

    def readdir(self, path, fh):
        dirents = ['.', '..']
        if path in '/':
            for gpx in self.track_dir:
                dirents.extend([gpx])
        else:
            id = self.track_dir[path[1:]][0]
            data = requests.get(_urlget % id, auth=(self.user, self.password))
            extension = re.sub(r'.*filename="[^"]+?(\.[^"]+)"', r'\1',
                               data.headers['Content-Disposition'])
            self.track_dir[path[1:]][1] = data
            dirents.append(str(len(data.content)) + extension)
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
    parser.add_argument('-p', dest='password', nargs=1, help='Password')
    parser.add_argument('-d', dest='debug', action='store_true', help='Debug mode')

    args = parser.parse_args()
    if not args.password:
        raise Exception('Password is mandatory!')

    FUSE(OsmTraces(args.user[0], args.password[0]), args.mountpoint[0], nothreads=True, foreground=True,
         debug=args.debug)


if __name__ == '__main__':
    main()