if not __debug__:
    raise RuntimeError('Qualification requires Python assertions enabled')
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"data":[]}')

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert body['messages'][0]['content'] == 'PRIVATE_PROMPT_LINUX_WALK'
        with open('/arrivals', 'a') as f:
            f.write('1\n')
        model = body['model']
        content = 'PRIVATE_RESPONSE_LINUX_WALK'
        usage = {'prompt_tokens': 4, 'completion_tokens': 3, 'total_tokens': 7}
        if body.get('stream'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            for delta, finish in [({'content': content}, None), ({}, 'stop')]:
                event = {'id': 'walk', 'object': 'chat.completion.chunk', 'model': model,
                         'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish}]}
                if finish:
                    event['usage'] = usage
                self.wfile.write(('data: '+json.dumps(event)+'\n\n').encode())
                self.wfile.flush()
            self.wfile.write(b'data: [DONE]\n\n')
            return
        result = {'id': 'walk', 'object': 'chat.completion', 'model': model,
                  'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': content}, 'finish_reason': 'stop'}], 'usage': usage}
        raw = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

HTTPServer(('0.0.0.0', 8090), Handler).serve_forever()
