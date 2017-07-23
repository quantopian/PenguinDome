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
