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

import datetime
import dateutil.parser
from json import (
    JSONEncoder,
    dump as real_dump,
    load as real_load,
    dumps as real_dumps,
    loads as real_loads,
)


class MyJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return JSONEncoder.default(self, obj)


def object_hook(dct):
    for key in dct.keys():
        if key.endswith('_at'):
            try:
                dct[key] = dateutil.parser.parse(dct[key])
            except:
                pass
        return dct


def dump(*args, **kwargs):
    return real_dump(cls=MyJSONEncoder, *args, **kwargs)


def dumps(*args, **kwargs):
    return real_dumps(cls=MyJSONEncoder, *args, **kwargs)


def load(*args, **kwargs):
    return real_load(object_hook=object_hook, *args, **kwargs)


def loads(*args, **kwargs):
    return real_loads(object_hook=object_hook, *args, **kwargs)
