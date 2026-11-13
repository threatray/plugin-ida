import os
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List
from unittest.mock import MagicMock, patch

from hamcrest import assert_that, calling, instance_of, is_, none, raises

from threatray_ida.adapters.threatray_api_error import ThreatrayApiError
from threatray_ida.adapters.threatray_api_impl import (
    PE_HEADER_THREAD_NAME,
    ThreatrayApiImpl,
    _TrackedHTTPConnection,
    cancel_requests,
    request,
)
from threatray_ida.application.settings_provider import SettingsProvider

JOIN_SECONDS = 5.0


class TestRequestCancellation(unittest.TestCase):
    def setUp(self) -> None:
        self.received = threading.Event()
        self.release = threading.Event()
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # pylint: disable=invalid-name
                if self.path == '/slow':
                    test.received.set()
                    test.release.wait(60)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'{}')

            def log_message(self, *_args) -> None:
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.release.set)

    def test_a_request_waiting_for_the_server_fails_as_soon_as_it_is_canceled(self) -> None:
        outcome: List[object] = []

        def run() -> None:
            try:
                outcome.append(request('GET', f'{self.url}/slow'))
            except ThreatrayApiError as e:
                outcome.append(e)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        assert_that(self.received.wait(JOIN_SECONDS), is_(True))

        cancel_requests()
        worker.join(JOIN_SECONDS)

        assert_that(worker.is_alive(), is_(False))
        assert_that(outcome[0], instance_of(ThreatrayApiError))

    def test_requests_work_again_after_a_cancel(self) -> None:
        request('GET', f'{self.url}/fast')
        cancel_requests()

        assert_that(request('GET', f'{self.url}/fast'), is_({}))

    def test_a_request_through_a_proxy_is_canceled_too(self) -> None:
        silent_proxy = socket.socket()
        silent_proxy.bind(('127.0.0.1', 0))
        silent_proxy.listen()
        self.addCleanup(silent_proxy.close)
        outcome: List[object] = []

        def run() -> None:
            try:
                outcome.append(request('GET', 'http://threatray.invalid/v1/functions'))
            except ThreatrayApiError as e:
                outcome.append(e)

        proxy = f'http://127.0.0.1:{silent_proxy.getsockname()[1]}'
        with patch.dict(os.environ, {'HTTP_PROXY': proxy, 'http_proxy': proxy, 'NO_PROXY': '', 'no_proxy': ''}):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            connection, _ = silent_proxy.accept()
            self.addCleanup(connection.close)
            connection.recv(1)  # the request has been sent and now waits for an answer that never comes

            cancel_requests()
            worker.join(JOIN_SECONDS)

        assert_that(worker.is_alive(), is_(False))
        assert_that(outcome[0], instance_of(ThreatrayApiError))

    def test_a_request_canceled_while_it_connects_is_not_sent(self) -> None:
        host, port = self.server.server_address[:2]
        connection = _TrackedHTTPConnection(str(host), port)
        self.addCleanup(connection.close)

        cancel_requests()  # arrives after the request was started, before the connection is established

        with self.assertRaisesRegex(OSError, 'canceled'):
            connection.connect()
        assert_that(connection.sock, none())

    def test_the_helper_thread_of_a_request_does_not_delay_the_exit_of_the_process(self) -> None:
        settings_provider = MagicMock(spec=SettingsProvider)
        settings_provider.get_realm.return_value = 'dummy'
        api = ThreatrayApiImpl(settings_provider)
        blocked = threading.Event()
        self.addCleanup(blocked.set)

        module = 'threatray_ida.adapters.threatray_api_impl'
        with patch(f'{module}._fetch_pe_header', side_effect=lambda **_: blocked.wait(60)), \
                patch(f'{module}.request', side_effect=ThreatrayApiError('failed')):
            assert_that(calling(api.get_functions).with_args('hash'), raises(ThreatrayApiError))
            helpers = [thread for thread in threading.enumerate() if thread.name == PE_HEADER_THREAD_NAME]

        assert_that([thread.daemon for thread in helpers], is_([True]))
