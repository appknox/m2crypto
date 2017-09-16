#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os

from M2Crypto.BIO import openfile

logging.basicConfig(format='%(levelname)s:%(funcName)s:%(message)s',
                    level=logging.DEBUG)

f = openfile('/tmp/test.txt', 'w')
logging.debug('f = %s', f)
ret = f.write('Zemské desky')
logging.debug('ret = %s', ret)
logging.debug('f.pyfile = dir %s', dir(f.pyfile))
f.close()
logging.debug('f = %s', f)
size = os.stat('/tmp/test.txt')
logging.debug('size = %d', size.st_size)
