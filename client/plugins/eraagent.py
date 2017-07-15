#!/usr/bin/env python

import json
import os
import psutil

binary_paths = ('/opt/eset/RemoteAdministrator/Agent/ERAAgent',)

results = {}

results['installed'] = any(os.path.exists(path) for path in binary_paths)
results['running'] = any(p.exe() == b
                         for b in binary_paths
                         for p in psutil.process_iter())

print(json.dumps(results))
