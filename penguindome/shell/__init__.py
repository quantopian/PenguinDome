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

from abc import ABCMeta, abstractmethod
from base64 import b64encode, b64decode
import select
import os
import socket
import sys
import time
from uuid import uuid4

from penguindome.client import server_request
from penguindome.encryption import Encryptor


class InteractionPeer(metaclass=ABCMeta):
    @abstractmethod
    def receive(self, timeout=None):
        """Read and return any pending data or None or raise EOFError

        Blocks if `timeout` is None, otherwise waits up until the specified
        number of seconds
        """
        pass

    @abstractmethod
    def send(self, data):
        """Send the specified data to the peer or raise EOFError"""
        pass

    @abstractmethod
    def poll(self, timeout=None):
        """Check for pending data

        Blocks if `timeout` is None, or waits for the specified # of seconds.

        Raises EOFError if no more data is forthcoming.
        """
        pass

    @abstractmethod
    def close(self):
        """Tell the peer we're all done"""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class InteractionBroker(object):
    """Generic class for mediating a conversation between two objects"""

    def __init__(self, peer1, peer2, poll_interval=1):
        """`peer` and `peer2` are subclass objects of InteractionPeer"""
        self.peers = (peer1, peer2)
        self.poll_interval = poll_interval

    def interact(self):
        """Interacts until EOF from one peer, then closes both peers"""
        directions = (self.peers, tuple(reversed(self.peers)))
        while True:
            start = time.time()
            for direction in directions:
                try:
                    received = direction[0].receive(timeout=0)
                    if not received:
                        continue
                    direction[1].send(received)
                except EOFError:
                    return
            end = time.time()
            if end - start < self.poll_interval:
                time.sleep(self.poll_interval - (end - start))


class TerminalPeer(InteractionPeer):
    def __init__(self):
        self.done = False
        self.pending_data = b''
        self.poller = select.poll()
        self.fd = os.fdopen(sys.stdin.fileno(), 'r+b', 0)
        self.poller.register(self.fd, select.POLLIN)
        self.primed_state = None

    def receive(self, timeout=None):
        self.poll(timeout=timeout)
        if self.pending_data:
            ret = self.pending_data
            self.pending_data = b''
            return ret
        if self.done:
            raise EOFError()

    def send(self, data):
        try:
            sys.stdout.buffer.raw.write(data)
        except BrokenPipeError:
            self.done = True
            raise EOFError()

    def poll(self, timeout=None):
        if self.pending_data:
            return True
        while not self.done:
            event = self.poller.poll(timeout)
            if not event:
                return False
            flags = event[0][1]
            if flags & select.POLLIN:
                got = self.fd.read(1)
                if got:
                    # [\r\n]~. exits.
                    if got in (b'\r', b'\n'):
                        self.primed_state = 'NEWLINE'
                    elif got == b'~' and self.primed_state == 'NEWLINE':
                        self.primed_state = 'TILDE'
                    elif self.primed_state == 'TILDE':
                        if got == b'.':
                            raise EOFError()
                        self.pending_data += b'~'
                        self.primed_state = None
                    else:
                        self.primed_state = None
                    self.pending_data += got
                else:
                    self.done = True
            if flags & (select.POLLERR | select.POLLHUP):
                self.done = True
        if self.pending_data:
            return True
        if self.done:
            raise EOFError()

    def close(self):
        pass


class PenguinDomeServerPeer(InteractionPeer):
    def __init__(self, peer_type, pipe_id=None, local_port=None, logger=None,
                 client_hostname=None):
        if peer_type not in ('client', 'server'):
            raise Exception('Invalid peer type "{}"'.format(peer_type))
        self.type = peer_type
        self.pipe_id = pipe_id
        self.pending_data = b''
        self.done = False
        self.local_port = local_port
        self.logger = logger
        self.client_hostname = client_hostname
        data = {'encryption_key': uuid4().hex,
                'encryption_iv': uuid4().hex,
                'hostname': socket.gethostname()}
        if self.pipe_id is None:
            if not client_hostname:
                raise Exception("Can't create server pipe without specifying "
                                "client_hostname")
            data['client_hostname'] = client_hostname
            response = self._request('create', data=data)
            self.pipe_id = response['pipe_id']
        else:
            response = self._request('open', data=data)
        self.encryptors = {
            'send': Encryptor(data['encryption_key'], data['encryption_iv']),
            'receive': Encryptor(data['encryption_key'], data['encryption_iv'])
        }

    def _request(self, request, data=None):
        if data is None:
            data = {}
        else:
            data = data.copy()
        if self.pipe_id:
            data['pipe_id'] = self.pipe_id
        response = server_request(
            '/penguindome/v1/server_pipe/{}/{}'.format(self.type, request),
            data=data, local_port=self.local_port, logger=self.logger,
            signed=request not in ('send', 'receive'))
        if response.status_code == 404:
            raise FileNotFoundError('Pipe ID {} not found'.format(
                self.pipe_id))
        response.raise_for_status()
        return response.json()

    def receive(self, timeout=None):
        self.poll(timeout=timeout)
        ret = self.pending_data
        self.pending_data = b''
        return ret

    def send(self, data):
        if self.done:
            raise EOFError()
        encrypted_data = self.encryptors['send'].encrypt(data)
        encoded_data = b64encode(encrypted_data).decode('utf8')
        data = self._request('send', {'data': encoded_data})
        if 'eof' in data and data['eof']:
            self.done = True
            raise EOFError()

    def poll(self, timeout=None):
        if self.pending_data:
            return True
        if self.done:
            raise EOFError()
        start = time.time()
        while True:
            data = self._request('receive')
            if 'data' in data and data['data']:
                break
            if timeout is not None:
                elapsed = time.time() - start
                remaining = timeout - elapsed
                if remaining < 0:
                    break
            time.sleep(remaining if timeout is not None else 1)
        if 'data' in data and data['data']:
            encoded_data = data['data']
            encrypted_data = b64decode(encoded_data)
            decrypted_data = self.encryptors['receive'].decrypt(encrypted_data)
            self.pending_data += decrypted_data
        if 'eof' in data and data['eof']:
            self.done = True
        if self.pending_data:
            return True
        if self.done:
            raise EOFError()
        return False

    def close(self):
        try:
            self._request('close')
        except Exception:
            pass

    def __enter__(self):
        if self.done:
            raise EOFError()
        return self
