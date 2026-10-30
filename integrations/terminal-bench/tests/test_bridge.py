import io
import json
import os
from pathlib import Path
import socket
import sys
import threading
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb.bridge import ExternalEngine

class BridgeTests(unittest.TestCase):
    def test_cross_request_reply_closes_guard_channel(self):
        class Journal:
            def emit(self,*args,**kwargs):pass
        class Observer:
            stdin=io.BytesIO()
            def poll(self):return None
        engine=ExternalEngine.__new__(ExternalEngine);engine.parent,client=socket.socketpair();engine.failed=None;engine.journal=Journal();engine.observer=Observer()
        r,w=os.pipe();engine.observer_reader=os.fdopen(r,'rb')
        request=dict(id=1,op='entry',path='/app/task',limit=None)
        wrong=dict(request, id=2)
        os.write(w,json.dumps(dict(request=wrong,value=dict(kind='file'))).encode()+b'\n');os.close(w)
        t=threading.Thread(target=engine._observations);t.start()
        client.sendall(json.dumps(request).encode()+b'\n');client.settimeout(2)
        self.assertEqual(client.recv(16),b'')
        t.join(timeout=2);self.assertFalse(t.is_alive())
        self.assertIn('Cross-request',engine.failed)
        engine.parent.close();client.close();engine.observer_reader.close()

if __name__=='__main__':unittest.main()
