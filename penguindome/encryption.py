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

from Crypto import Random
from Crypto.Cipher import AES
import hashlib


def make_aes_key(key):
    return hashlib.sha256(key.encode()).digest()


def make_aes_iv(iv=None):
    if not iv:
        return Random.new().read(AES.block_size)
    else:
        return make_aes_key(iv)[0:AES.block_size]


class BadDataError(Exception):
    pass


class Encryptor(object):
    """Actually, it's an Encryptor / Decryptor.

    If you use an Encryptor object to encrypt, then the encrypted blocks are
    chained, which means they have to be decrypted in the same order at the
    other end. If you want each encrypted message instead to stand alone, then
    use `encrypt()` and `decrypt()` below to do unchained encryption.
    """

    # There's nothing special about this sequence of characters, it's just two
    # random bytes I made up to confirm that decryption worked. After the magic
    # number comes an integer representing the length of the encrypted message,
    # then a colon, then the message, then padding to a multiple of 16 bytes.
    magic_number = b'\xd1\x08'

    def __init__(self, key, iv=None):
        self.iv = make_aes_iv(iv)
        self.aes = AES.new(make_aes_key(key), AES.MODE_CBC, self.iv)
        self.random = Random.new()

    def encrypt(self, msg):
        blob = self.magic_number
        blob += '{}:'.format(len(msg)).encode()
        blob += msg.encode() if isinstance(msg, str) else msg
        overage = len(blob) % AES.block_size
        if overage:
            need_padding = AES.block_size - overage
            blob += self.random.read(need_padding)
        return self.aes.encrypt(blob)

    def decrypt(self, msg):
        decrypted = self.aes.decrypt(msg)
        if decrypted[0:len(self.magic_number)] != self.magic_number:
            raise BadDataError('Encrypted message did not decrypt')
        decrypted = decrypted[len(self.magic_number):]
        num_str = ''
        i = 0
        while i < len(decrypted) and ord('0') <= decrypted[i] <= ord('9'):
            num_str += chr(decrypted[i])
            i += 1
        if i == len(decrypted) or decrypted[i] != ord(':'):
            raise BadDataError('Encrypted message did not decrypt')
        decrypted = decrypted[i + 1:i + 1 + int(num_str)]
        return decrypted


def encrypt(message, key, iv):
    return Encryptor(key, iv).encrypt(message)


def decrypt(message, key, iv):
    return Encryptor(key, iv).decrypt(message)
