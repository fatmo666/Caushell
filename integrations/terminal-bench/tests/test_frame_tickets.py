import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb.owned_frames import FrameServer

class TicketTests(unittest.TestCase):
    def test_unknown_or_replayed_ticket_does_not_reach_the_engine(self):
        import threading
        server=FrameServer.__new__(FrameServer);server.lock=threading.Lock();server.closed=False;server.pending={}
        with self.assertRaises(ValueError):server.accept(dict(ticket='unissued',nonce='n',cwd='/app',raw=[]))
        self.assertFalse(server.pending)

    def test_cross_action_nonce_and_cancellation_cannot_consume_another_action(self):
        import threading
        server=FrameServer.__new__(FrameServer);server.lock=threading.Lock();server.closed=False
        server.pending={'first':dict(tool_id='a',nonce='one'),'second':dict(tool_id='b',nonce='two')}
        with self.assertRaises(ValueError):server.accept(dict(ticket='first',nonce='two',cwd='/app',raw=[]))
        self.assertEqual(len(server.pending),2)
        server.cancel('a')
        with self.assertRaises(ValueError):server.accept(dict(ticket='first',nonce='one',cwd='/app',raw=[]))
        self.assertEqual(set(server.pending),{'second'})

if __name__=='__main__':unittest.main()
