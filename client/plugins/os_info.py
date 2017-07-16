#!/usr/bin/env python3

import json
import platform

distname, version, _ = platform.linux_distribution()

results = {
    'distname': distname,
    'version': version,
}

print(json.dumps(results))
