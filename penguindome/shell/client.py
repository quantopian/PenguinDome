# Quantopian, Inc. licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import pexpect

from penguindome.shell import InteractionPeer


class PexpectPeer(InteractionPeer):
    def __init__(self, *args, **kwargs):
        """Arguments are passed onto `pexpect.spawn`"""
        self.child = pexpect.spawn(*args, **kwargs)
        self.pending_data = b''
        self.done = False

    def receive(self, timeout=None):
        self.poll(timeout=timeout)
        if self.pending_data:
            ret = self.pending_data
            self.pending_data = b''
            return ret
        if self.done:
            raise EOFError('Child process is done')

    def send(self, data):
        try:
            self.child.send(data)
        except:
            self.done = True
            raise EOFError('Error sending data to child')

    def poll(self, timeout=None):
        if self.pending_data:
            return True
        if self.done:
            raise EOFError('Child process is done')
        if timeout is None:
            timeout = 0
        while True:
            try:
                self.child.expect(r'.', timeout=timeout)
            except pexpect.TIMEOUT:
                return True if self.pending_data else False
            except pexpect.EOF:
                self.pending_data += self.child.before
                self.done = True
                if self.pending_data:
                    return True
                raise EOFError('Child process is done')
            else:
                self.pending_data += self.child.before + self.child.after

    def close(self):
        self.child.close()
