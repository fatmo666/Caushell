"""Native nonstream fallback is transported byte-for-byte and audited as JSON."""
import contextlib,http.client,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb import provider

RAW=b'{ "id":"fixture-json", "type":"message", "role":"assistant", "model":"deepseek-flash", "stop_reason":"end_turn", "content":[{"type":"thinking","thinking":"fixture","signature":"native"},{"type":"text","text":"done"}], "usage":{"input_tokens":9,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":3} }'
class Socket:
 def settimeout(self,_):pass
 def shutdown(self,*_):pass
class Response:
 status=200
 def __init__(self):self.raw=RAW
 def getheader(self,_name,_default=None):return 'application/json'
 def read(self,_size):
  raw,self.raw=self.raw,b'';return raw
class Connection:
 calls=[];debuglevel=0
 def __init__(self,*_,**__):self.sock=Socket()
 def connect(self):pass
 def request(self,*args,**kwargs):self.calls.append((args,kwargs))
 def getresponse(self):return Response()
 def close(self):pass
class NativeJSON(unittest.TestCase):
 def test_complete_native_json_retains_thinking_and_usage(self):
  s=provider.MessageStream();s.message(RAW)
  self.assertTrue(s.complete);self.assertEqual(s.usage['output_tokens'],3)
  self.assertEqual(s.blocks[0]['signature'],'native')
 def test_missing_usage_is_rejected(self):
  v=json.loads(RAW);del v['usage']['output_tokens']
  with self.assertRaisesRegex(ValueError,'authoritative output usage'):provider.MessageStream().message(json.dumps(v))
 def test_error_or_truncated_response_is_not_a_settled_message(self):
  for raw in [b'{"type":"error","error":{"message":"failed"}}',RAW[:-1]]:
   with self.subTest(raw=raw[:30]),self.assertRaises(ValueError):provider.MessageStream().message(raw)
 def test_real_relay_forwards_original_nonstream_bytes_without_extra_calls(self):
  Connection.calls=[]
  def account(_config,path):provider.save(path,dict(fixture=True,model_requests=0))
  with tempfile.TemporaryDirectory() as d,patch.object(provider.http.client,'HTTPSConnection',Connection),patch.object(provider,'load_key',return_value='fixture-not-a-secret',create=True),patch.object(provider,'account_snapshot',side_effect=account,create=True):
   folder=Path(d)/'provider';p=provider.Provider(folder,dict(base_url='https://fixture.invalid',model='deepseek-flash'))
   u=urlsplit(p.url.replace('host.docker.internal','127.0.0.1')+'/v1/messages')
   c=http.client.HTTPConnection(u.hostname,u.port,timeout=5)
   raw=b'{ "model":"deepseek-flash", "stream":false, "thinking":{"type":"adaptive"}, "max_tokens":32000 }'
   try:
    c.request('POST',u.path,body=raw,headers={'Content-Type':'application/json'})
    response=c.getresponse();self.assertEqual(response.status,200);self.assertEqual(response.read(),RAW)
   finally:c.close();p.close()
   self.assertEqual(len(Connection.calls),1)
   self.assertEqual(Connection.calls[0][1]['body'],raw)
   self.assertEqual(next(folder.glob('*-response.json')).read_bytes(),RAW)
   self.assertEqual(next(folder.glob('*-request.raw')).read_bytes(),raw)
   receipt=json.loads(next(folder.glob('*-usage.json')).read_text())
   self.assertEqual(receipt['usage']['output_tokens'],3)
   self.assertEqual(receipt['stream']['events'],dict(nonstream_message=1))
if __name__=='__main__':unittest.main(verbosity=2)
