import asyncio
import unittest

from nexhunt.services.privacy_route import PrivacyRouteError, PrivacyRouteManager, _mask_proxy


class PrivacyRouteTests(unittest.TestCase):
    def test_supported_proxy_is_parsed_for_proxychains(self):
        self.assertEqual(
            PrivacyRouteManager._parse_proxy("socks5h://alice:secret@127.0.0.1:9050"),
            ("socks5", "127.0.0.1", 9050, "alice", "secret"),
        )

    def test_unsafe_or_incomplete_proxy_is_rejected(self):
        for value in (
            "ftp://host:21", "socks5://host", "host:9050",
            "socks5://user:bad%0apassword@host:9050", "http://host:8080/path",
        ):
            with self.subTest(value=value), self.assertRaises(PrivacyRouteError):
                PrivacyRouteManager._parse_proxy(value)

    def test_proxy_password_is_masked(self):
        self.assertEqual(
            _mask_proxy("socks5://alice:secret@proxy.example:1080"),
            "socks5://alice:***@proxy.example:1080",
        )

    def test_system_mode_does_not_stack_application_proxy(self):
        manager = PrivacyRouteManager()
        asyncio.run(manager.apply("system"))
        self.assertEqual(manager.mode, "system")
        self.assertEqual(manager.proxy_url, "")
        asyncio.run(manager.stop())


if __name__ == "__main__":
    unittest.main()
