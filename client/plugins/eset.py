#!/usr/bin/env python

import json
import os
import psutil
import time

binary_paths = ('/opt/eset/esets/sbin/esets_daemon',)
defn_paths = ('/var/opt/eset/esets/lib/data/data.txt',)

results = {}

results['installed'] = any(os.path.exists(path) for path in binary_paths)
results['running'] = any(p.exe() == b
                         for b in binary_paths
                         for p in psutil.process_iter())
results['recent'] = any(os.path.exists(p) and
                        time.time() - os.stat(p).st_mtime < 60 * 60 * 24 * 2
                        for p in defn_paths)

print(json.dumps(results))
