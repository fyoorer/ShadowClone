# Copyright 2018 IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os


class FilePair(object):
    def __init__(self, key, fileobj):
        ''' Create a file pair object - used by ascp to transfer a group of files
            key - object name on ibmcos
            fileobj - file or folder/name on local system '''
        self.key = key
        self.fileobj = fileobj


def check_io_access(ioobj, access, is_file=False):
    ''' check if a file/folder exists and has a given IO access '''
    if ((is_file and not os.path.isfile(ioobj)) or
        (not is_file and not os.path.isdir(ioobj)) or
            not os.access(ioobj, access)):
            _objtype = "File" if is_file else "Directory"
            raise IOError("Error accessing %s: %s" % (_objtype, ioobj))
