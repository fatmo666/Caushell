"""Pluggable native Anthropic relay for the local Strata service.

No protocol conversion, hidden model turn, reasoning rewrite or request cap.
The exact inbound request and upstream SSE are retained before interpretation.
"""
from collections import Counter
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import socket
import threading
import time
from urllib.parse import urlsplit
import uuid

from .journal import BufferedJournal
from .contract import save
from rq3.records import stamp


class MessageStream:
    """Inspect native SSE without changing anything delivered to the client."""
    def __init__(self):
        self.data = []
        self.events = Counter()
        self.blocks = {}
        self.arguments = {}
        self.closed = set()
        self.usage = {}
        self.message_id = None
        self.model = None
        self.stop_reason = None
        self.complete = False
        self.errors = []

    def line(self, raw):
        line = raw.rstrip(b"\r\n")
        if line.startswith(b"data:"):
            self.data.append(line[5:].lstrip(b" "))
        elif not line and self.data:
            return self.flush()
        return None

    def flush(self):
        if not self.data:
            return None
        event = json.loads(b"\n".join(self.data))
        self.data.clear()
        kind = event["type"]
        self.events[kind] += 1
        if kind == "message_start":
            message = event["message"]
            self.message_id, self.model = message["id"], message.get("model")
            self.usage.update(message.get("usage", {}))
        elif kind == "content_block_start":
            index = event["index"]
            if index in self.blocks:
                raise ValueError("Duplicate content-block index")
            self.blocks[index] = deepcopy(event["content_block"])
        elif kind == "content_block_delta":
            index, delta = event["index"], event["delta"]
            block = self.blocks[index]
            if delta["type"] == "input_json_delta":
                self.arguments[index] = self.arguments.get(index, "") + delta["partial_json"]
            else:
                key = {"text_delta": "text", "thinking_delta": "thinking", "signature_delta": "signature"}.get(delta["type"])
                if key:
                    block[key] = block.get(key, "") + delta[key]
        elif kind == "content_block_stop":
            index = event["index"]
            if index in self.arguments:
                self.blocks[index]["input"] = json.loads(self.arguments[index])
            self.closed.add(index)
        elif kind == "message_delta":
            self.stop_reason = event.get("delta", {}).get("stop_reason", self.stop_reason)
            self.usage.update(event.get("usage", {}))
        elif kind == "message_stop":
            self.complete = True
        elif kind == "error":
            self.errors.append(event.get("error"))
        return event

    def finish(self):
        self.flush()
        if not self.complete or self.errors or set(self.blocks) != self.closed:
            raise ValueError("Incomplete native Messages stream")
        if "output_tokens" not in self.usage:
            raise ValueError("No authoritative output usage in native stream")
        return dict(role="assistant", content=[self.blocks[i] for i in sorted(self.blocks)])

    def summary(self):
        return dict(events=dict(self.events), message_id=self.message_id, model=self.model,
                    stop_reason=self.stop_reason, usage=self.usage, complete=self.complete,
                    content_block_types=dict(Counter(b["type"] for b in self.blocks.values())),
                    thinking_characters=sum(len(b.get("thinking", "")) for b in self.blocks.values()),
                    errors=self.errors)


class Provider:
    def __init__(self, folder, config):
        self.config = config
        upstream = urlsplit(self.config["base_url"])
        if upstream.username or upstream.password or upstream.query or upstream.fragment:
            raise ValueError("Endpoint must not contain credentials or query parameters")
        if upstream.scheme not in ("http", "https"):
            raise ValueError("Unsupported local provider transport")
        if upstream.scheme == "http" and upstream.hostname not in ("localhost", "127.0.0.1"):
            raise ValueError("Non-loopback upstream must use verified TLS")
        self.folder = folder
        folder.mkdir()
        self.journal = BufferedJournal(folder / "events.jsonl", dict(role="local_provider"))
        self.stopped = threading.Event()
        self.counts = dict(requests=0, settled=0, failed=0)
        self.lock = threading.Lock()
        self.connections = set()
        self.sockets = set()
        token = uuid.uuid4().hex
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if self.path.split("?", 1)[0] != f"/{token}/v1/messages":
                    self.send_error(404)
                    return
                ident = str(uuid.uuid4())
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                save(folder / (ident + "-request.json"), body)
                if (body.get("model") != outer.config["model"] or not body.get("stream")
                        or body.get("thinking", {}).get("type") == "disabled"):
                    outer.journal.emit("invalid_configuration", request_id=ident,
                                       model=body.get("model"), thinking=body.get("thinking"))
                    self.send_error(400, "Model, stream or thinking configuration rejected")
                    return
                with outer.lock:
                    outer.counts["requests"] += 1
                began = stamp()
                outer.journal.emit("provider_dispatch", _stamp=began, request_id=ident)
                cls = http.client.HTTPSConnection if upstream.scheme == "https" else http.client.HTTPConnection
                connection = cls(upstream.hostname, upstream.port, timeout=30)
                with outer.lock:
                    outer.connections.add(connection)
                inspection = MessageStream()
                disconnected, headers_sent = False, False
                marks = {}
                status = None
                transport = None
                try:
                    connection.connect()
                    transport = connection.sock
                    transport.settimeout(None)
                    with outer.lock:
                        outer.sockets.add(transport)
                    if outer.stopped.is_set():
                        raise RuntimeError("Trial already ended")
                    # Request and response bodies remain native Anthropic data.
                    connection.request("POST", outer.config.get("messages_path", "/v1/messages"),
                                       body=json.dumps(body).encode(), headers={
                                           "anthropic-version": "2023-06-01", "Content-Type": "application/json"})
                    response = connection.getresponse()
                    status = response.status
                    outer.journal.emit("provider_headers", request_id=ident, status=status,
                                       content_type=response.getheader("Content-Type"))
                    self.send_response(status)
                    self.send_header("Content-Type", response.getheader("Content-Type", "text/event-stream"))
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    headers_sent = True
                    with (folder / (ident + "-response.sse")).open("xb") as transcript:
                        for line in response:
                            transcript.write(line)
                            at = stamp()
                            if "first_byte_ns" not in marks:
                                marks["first_byte_ns"] = at["monotonic_ns"] - began["monotonic_ns"]
                                outer.journal.emit("provider_first_byte", _stamp=at, request_id=ident,
                                                   elapsed_ns=marks["first_byte_ns"])
                            event = inspection.line(line) if status == 200 else None
                            if event:
                                if event["type"] == "content_block_delta":
                                    if "first_content_ns" not in marks:
                                        marks["first_content_ns"] = at["monotonic_ns"] - began["monotonic_ns"]
                                        outer.journal.emit("provider_first_content", _stamp=at, request_id=ident,
                                                           elapsed_ns=marks["first_content_ns"])
                                    delta_type = event["delta"]["type"]
                                    name = {"thinking_delta": "first_thinking_ns", "text_delta": "first_text_ns",
                                            "input_json_delta": "first_tool_argument_ns"}.get(delta_type)
                                    if name and name not in marks:
                                        marks[name] = at["monotonic_ns"] - began["monotonic_ns"]
                                outer.journal.emit("provider_stream_event", _stamp=at, request_id=ident,
                                                   type=event["type"], index=event.get("index"),
                                                   delta_type=event.get("delta", {}).get("type"), bytes=len(line))
                            if not disconnected:
                                try:
                                    self.wfile.write(line)
                                    self.wfile.flush()
                                except (BrokenPipeError, ConnectionResetError):
                                    disconnected = True
                                    outer.journal.emit("client_disconnected", request_id=ident)
                    if status != 200:
                        raise ValueError(f"Local provider HTTP {status}")
                    inspection.finish()
                    settled = dict(request_id=ident, message_id=inspection.message_id, usage=inspection.usage,
                                   elapsed_ns=time.monotonic_ns() - began["monotonic_ns"],
                                   response_model=inspection.model, timing=marks, stream=inspection.summary())
                    save(folder / (ident + "-usage.json"), settled)
                    outer.journal.emit("provider_settled", **settled)
                    with outer.lock:
                        outer.counts["settled"] += 1
                except Exception as error:
                    outer.journal.emit("provider_failure", request_id=ident, error=repr(error),
                                       usage=inspection.usage, http_status=status)
                    save(folder / (ident + "-failure.json"), dict(error=repr(error), status=status,
                                                                stream=inspection.summary()))
                    with outer.lock:
                        outer.counts["failed"] += 1
                    if not headers_sent:
                        self.send_error(502, "Local upstream connection failed; inspect retained evidence")
                finally:
                    connection.close()
                    with outer.lock:
                        outer.connections.discard(connection)
                        outer.sockets.discard(transport)

        self.server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.server.daemon_threads = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.url = f"http://host.docker.internal:{self.server.server_port}/{token}"
        self.thread.start()

    def close(self):
        # End only this trial's active transports; preserve partial SSE as failures.
        self.stopped.set()
        self.server.shutdown()
        with self.lock:
            active = list(self.connections)
            sockets = list(self.sockets)
        for transport in sockets:
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for connection in active:
            if connection.sock is not None:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection.close()
        self.server.server_close()
        self.thread.join()
        self.journal.close()
        save(self.folder / "summary.json", dict(**self.counts, limits=None, paid_model_calls=0,
                                               backend="strata_native_anthropic", journal=self.journal.overhead()))
