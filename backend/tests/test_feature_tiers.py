import unittest

from fastapi.routing import APIRoute

from nexhunt.main import app


def _route(path: str, method: str = "POST") -> APIRoute:
    return next(
        route
        for route in app.routes
        if isinstance(route, APIRoute)
        and route.path == path
        and method in route.methods
    )


def _pro_features(path: str, method: str = "POST") -> list[str]:
    features: list[str] = []
    for dependency in _route(path, method).dependant.dependencies:
        call = dependency.call
        if getattr(call, "__name__", "") != "_dep" or not call.__closure__:
            continue
        features.extend(
            cell.cell_contents
            for cell in call.__closure__
            if isinstance(cell.cell_contents, str)
        )
    return features


class FeatureTierTests(unittest.TestCase):
    def test_free_attack_features_have_no_pro_dependency(self):
        free_routes = [
            "/api/pipeline/xss",
            "/api/proxy/intruder/start",
            "/api/wordpress/scan",
            "/api/bruteforce/start",
        ]
        for path in free_routes:
            with self.subTest(path=path):
                self.assertEqual(_pro_features(path), [])

    def test_advanced_pipelines_remain_pro(self):
        self.assertEqual(
            _pro_features("/api/pipeline/sqli_probe"),
            ["SQLi Probe pipeline"],
        )
        self.assertEqual(
            _pro_features("/api/pipeline/js_scan"),
            ["JS Secrets pipeline"],
        )


if __name__ == "__main__":
    unittest.main()
