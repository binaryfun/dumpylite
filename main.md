# Introduction #

python Dumpy.py


# Details #

dumpy@ghosting:~/web/testing$ ls
Dumpy.py  http\_gzip.cap

dumpy@ghosting:~/web/testing$ python Dumpy.py
NUMBER OF PACKETS
10 (0 - 9)

########## TESTING SQLITEDUMP ##########
{'src': '00:0a:95:67:49:3c', 'dst': '00:c0:f0:2d:4a:a3', 'type': 2048}
{'reserved': 0L, 'seq': 2415239730, 'ack': 0, 'dataofs': 10L, 'urgptr': 0, 'window': 5840, 'flags': 2L, 'chksum': 40585, 'dport': 80, 'sport': 34059, 'options': [('MSS', 1460), ('SAckOK', ''), ('Timestamp', (2011387883, 0)), ('NOP', None), ('WScale', 7)]}

dumpy@ghosting:~/web/testing$ ls

Dumpy.py  http\_gzip.cap  http\_gzip.cap.db

dumpy@ghosting:~/web/testing$ sqlite3 http\_gzip.cap.db