#!/usr/bin/env python

import json
import platform

distname, version, _ = platform.linux_distribution()

results = {
    'distname': distname,
    'version': version,
}

print json.dumps(results)
