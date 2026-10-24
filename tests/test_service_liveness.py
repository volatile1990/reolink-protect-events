"""Progress watchdogs must not hide stuck workers or lose persistent state."""
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from reolink_protect_events.runtime import Runtime,WORKER_STALE_SECONDS
from reolink_protect_events.service_liveness import notify


class ProgressWatchdog(unittest.TestCase):
    def runtime(self):
        value=object.__new__(Runtime)
        value._state_lock=threading.Lock()
        value._native_thread=object()
        value._native_progress_at=100
        value._native_media_started=None
        value._delivery_retry_since=None
        value._delivery_progress_at=None
        value._last_delivery_ms=None
        value.capture_only=False
        return value

    def test_native_worker_must_progress_independently(self):
        value=self.runtime()
        self.assertTrue(value._watchdog_progress(100+WORKER_STALE_SECONDS-1))
        self.assertFalse(value._watchdog_progress(100+WORKER_STALE_SECONDS+1))

    def test_stuck_media_future_is_not_hidden_by_native_loop(self):
        value=self.runtime();value._native_progress_at=500;value._native_media_started=100
        self.assertFalse(value._watchdog_progress(500))
        value._native_media_started=None
        self.assertTrue(value._watchdog_progress(500))

    def test_capture_only_does_not_invent_native_stall(self):
        value=self.runtime();value._native_thread=None;value._native_progress_at=None
        self.assertTrue(value._watchdog_progress(100000))

    def test_notify_is_optional_and_checks_process_identity(self):
        with patch.dict(os.environ,{},clear=True):self.assertFalse(notify('WATCHDOG=1'))
        with patch.dict(os.environ,{'NOTIFY_SOCKET':'/not-used','WATCHDOG_PID':str(os.getpid()+1)},clear=True):
            self.assertFalse(notify('WATCHDOG=1'))

    def test_native_ready_does_not_hide_sustained_failed_outbox(self):
        value=self.runtime();value._native_thread=None
        health={'captureHealthy':True,'nativeReady':True,'pending':1,'retryIntervals':1,'lastNativeDeliveryMs':1}
        self.assertEqual(value._operator_alerts(health,100),[])
        self.assertEqual(value._operator_alerts(health,219),[])
        self.assertIn('events_delivery_unhealthy',[x['code']for x in value._operator_alerts(health,220)])
        health['pending']=health['retryIntervals']=0
        self.assertEqual(value._operator_alerts(health,221),[])

    def test_draining_healthy_outbox_does_not_alarm_for_old_event_start(self):
        value=self.runtime();value._native_thread=None
        for now in range(100,700,30):
            health={'captureHealthy':True,'nativeReady':True,'pending':1,'retryIntervals':0,
                    'lastNativeDeliveryMs':now,'oldestPendingAgeMs':999999999}
            self.assertEqual(value._operator_alerts(health,now),[])

    @unittest.skipUnless(os.name=='posix','Unix notification socket')
    def test_real_notification_socket(self):
        with tempfile.TemporaryDirectory()as directory:
            path=str(Path(directory)/'notify')
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)as listener:
                listener.bind(path);listener.settimeout(1)
                with patch.dict(os.environ,{'NOTIFY_SOCKET':path,'WATCHDOG_PID':str(os.getpid())}):
                    self.assertTrue(notify('READY=1\nWATCHDOG=1'))
                self.assertEqual(listener.recv(1024),b'READY=1\nWATCHDOG=1')


if __name__=='__main__':unittest.main()
