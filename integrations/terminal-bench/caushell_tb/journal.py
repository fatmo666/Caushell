"""Buffered evidence writer; the pinned RQ3 schema/chain stays compatible."""
import os
import threading
import time
from pathlib import Path
from rq3.records import Journal, canonical, stamp
import hashlib

class BufferedJournal:
    span=Journal.span
    verify=staticmethod(Journal.verify)
    overhead=Journal.overhead
    def __init__(self,path,context=None):
        self.path,self.context=Path(path),context or {};self.lock=threading.Lock()
        self.sequence,self.previous=0,'0'*64;self.write_ns=self.bytes_written=self.fsyncs=0
        self.stream=self.path.open('xb',buffering=65536)
    def emit(self,kind,_stamp=None,**data):
        observed=_stamp or stamp();began=time.monotonic_ns()
        with self.lock:
            row=dict(sequence=self.sequence,previous=self.previous,schema_version=2,**observed,pid=os.getpid(),thread_id=threading.get_ident(),context=self.context,kind=kind,data=data)
            row['sha256']=hashlib.sha256(canonical(row)).hexdigest();raw=canonical(row)+b'\n'
            self.stream.write(raw);self.stream.flush();self.previous=row['sha256'];self.sequence+=1;self.bytes_written+=len(raw);self.write_ns+=time.monotonic_ns()-began
            return row
    def close(self):
        self.stream.flush();os.fsync(self.stream.fileno());self.fsyncs+=1;self.stream.close()
