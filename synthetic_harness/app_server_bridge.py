"""Appended to the isolated relay source by bridge_source; no host imports."""


def app_server_main():
    sys.stdin.readline()  # Initial public observation; prompts come from host.
    Path('/tmp/work').mkdir()
    Path('/tmp/codex-home').mkdir()
    os.environ.update(CODEX_HOME='/tmp/codex-home', TMPDIR='/tmp/work')
    with HTTPServer(('127.0.0.1', 0), Relay) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        args = ['/opt/codex', 'app-server', '--listen', 'stdio://', '--strict-config']
        for key, value in STARTUP_CONFIG.items():
            args += ['-c', key + '=' + json.dumps(value)]
        try:
            with open('/tmp/app-server-stderr', 'w+') as errors:
                process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=errors, text=True)
                try:
                    message = {'ready': True, 'port': server.server_port}
                    while True:
                        reply = exchange({'op': 'app_server', 'message': message})
                        for command in reply['messages']:
                            process.stdin.write(json.dumps(command, separators=(',', ':')) + '\n')
                        process.stdin.flush()
                        if reply['stop']:
                            if reply.get('error'):
                                raise RuntimeError(reply['error'])
                            return
                        line = process.stdout.readline(65537)
                        if not line.endswith('\n') or len(line.encode()) > 65536:
                            raise RuntimeError('App-server EOF or oversized message')
                        message = json.loads(line)
                finally:
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=2)
                    process.stdin.close()
                    process.stdout.close()
                    errors.seek(0)
                    print(errors.read(8192), file=sys.stderr)
        finally:
            server.shutdown()
            worker.join()


app_server_main()
