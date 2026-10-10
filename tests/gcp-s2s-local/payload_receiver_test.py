import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from http.server import ThreadingHTTPServer

spec = importlib.util.spec_from_file_location('receiver', Path(__file__).with_name('payload-receiver.py'))
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


class ReceiverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), receiver.handler('OWNED_TEST_MARKER'))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            conn.request(method, path, body, headers or {})
            response = conn.getresponse()
            result = response.status, response.getheader('X-Payload-SHA256'), response.read()
            return result
        finally:
            conn.close()

    def test_download_marker_and_bounded_digests(self):
        self.assertEqual(self.request('GET', '/')[2], b'OWNED_TEST_MARKER')
        for size in (0, 1500, 65536, receiver.MAX_BYTES):
            status, digest, body = self.request('GET', '/bytes/' + str(size))
            self.assertEqual(status, 200)
            self.assertEqual(len(body), size)
            self.assertEqual(body[:256], bytes(range(256))[:min(size, 256)])
            self.assertEqual(digest, hashlib.sha256(body).hexdigest())

    def test_upload_receipt_and_rejection(self):
        for size in (0, 65536, receiver.MAX_BYTES):
            body = receiver.payload(size)
            status, _, reply = self.request('POST', '/upload', body)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(reply), {'received_length': size, 'received_sha256': hashlib.sha256(body).hexdigest()})
        self.assertEqual(self.request('GET', '/bytes/1048577')[0], 413)
        self.assertEqual(self.request('POST', '/upload', b'', {'Content-Length': '1048577'})[0], 413)
        self.assertEqual(self.request('POST', '/upload', b'', {'Transfer-Encoding': 'chunked'})[0], 400)
        self.assertEqual(self.request('GET', '/bytes/-1')[0], 404)


if __name__ == '__main__':
    unittest.main()
