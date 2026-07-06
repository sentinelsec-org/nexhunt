import unittest

from nexhunt.api.recon import (
    COMMON_TECHNOLOGY_ENDPOINTS,
    ENDPOINT_WORDLISTS,
    _technology_hints,
)


class EndpointTechnologyWordlistTests(unittest.TestCase):
    def test_common_technology_category_is_broad_and_within_scan_cap(self):
        self.assertGreaterEqual(len(COMMON_TECHNOLOGY_ENDPOINTS), 15)
        self.assertGreaterEqual(len(ENDPOINT_WORDLISTS["technologies"]), 100)
        all_routes = {route for routes in ENDPOINT_WORDLISTS.values() for route in routes}
        self.assertLessEqual(len(all_routes), 500)

    def test_results_receive_product_hints(self):
        self.assertEqual(
            _technology_hints("https://example.test/api/frontend/settings"),
            ["Grafana"],
        )
        self.assertEqual(
            _technology_hints("https://example.test/v1/sys/health"),
            ["HashiCorp Vault"],
        )
        self.assertEqual(_technology_hints("https://example.test/version"), [])


if __name__ == "__main__":
    unittest.main()
