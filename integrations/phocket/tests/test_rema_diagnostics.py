"""Only fixed diagnostics may leave supplier/network events."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from provider_login import RemaVerification
from coop_login import LoginError

class RemaDiagnosticsTests(unittest.TestCase):
    def test_completed_round_can_close_before_loop_is_reported(self):
        guard=RemaVerification()
        with patch('provider_login.time.monotonic',return_value=10):
            for _ in range(5):guard.response(SimpleNamespace(url='https://www.google.com/recaptcha/api2/userverify?private=not-stored',status=200))
            guard.check_loop()
        with patch('provider_login.time.monotonic',return_value=14):
            with self.assertRaisesRegex(LoginError,'REMA_VERIFICATION_LOOP'):guard.check_loop()
        self.assertNotIn('private',str(vars(guard)))

    def test_network_failures_ignore_normal_cancelled_requests_and_unknown_hosts(self):
        guard=RemaVerification()
        for _ in range(5):
            guard.request_failed(SimpleNamespace(url='https://www.google.com/recaptcha/api2/payload',failure='net::ERR_ABORTED'))
            guard.response(SimpleNamespace(url='https://www.google.com.evil.test/recaptcha/api2/userverify',status=403))
        self.assertEqual(guard.network_errors,0);self.assertEqual(guard.checks,0)
        for _ in range(3):guard.request_failed(SimpleNamespace(url='https://www.google.com/recaptcha/api2/reload',failure='net::ERR_NAME_NOT_RESOLVED'))
        with self.assertRaisesRegex(LoginError,'REMA_VERIFICATION_NETWORK'):guard.check_loop()

    def test_sms_rejection_and_rate_limit_have_fixed_messages(self):
        for status,code in [(400,'REMA_SMS_REJECTED'),(403,'REMA_SMS_REJECTED'),(429,'REMA_SMS_RATE_LIMIT')]:
            guard=RemaVerification();guard.response(SimpleNamespace(url='https://identitytoolkit.googleapis.com/v1/accounts:sendVerificationCode?key=not-stored',status=status))
            with self.assertRaisesRegex(LoginError,code):guard.check()
            self.assertNotIn('not-stored',str(vars(guard)))
        guard=RemaVerification();guard.response(SimpleNamespace(url='https://identitytoolkit.googleapis.com/v1/accounts:sendVerificationCode',status=200));guard.check()
