import os
import time
import requests
from cachetools import TTLCache

CACHE = TTLCache(maxsize=10000, ttl=3600)

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")

HEADERS = {
    "x-apikey": VT_KEY
}

VT_BASE = "https://www.virustotal.com/api/v3"


class VTClient:

    def __init__(self, min_interval=15):
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.min_interval = min_interval
        self._last_call = 0

    def _rate_limit(self):
        now = time.time()

        wait = self.min_interval - (now - self._last_call)

        if wait > 0:
            time.sleep(wait)

        self._last_call = time.time()

    def url_report(self, url: str):

        key = f"url:{url}"

        # Return cached result if available
        if key in CACHE:
            return CACHE[key]

        self._rate_limit()

        try:

            # Submit URL for analysis
            r = self.session.post(
                f"{VT_BASE}/urls",
                data={"url": url},
                timeout=15
            )

            if r.status_code not in (200, 201):
                return {
                    "verdict": "unknown",
                    "error": f"VirusTotal API error: {r.status_code}",
                    "details": r.text,
                    "positives": 0,
                    "total": 0
                }

            j = r.json()

            analysis_id = j["data"]["id"]

            # Poll analysis status
            for _ in range(6):

                time.sleep(2)

                ar = self.session.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    timeout=15
                )

                if ar.status_code != 200:
                    continue

                aj = ar.json()

                attrs = aj.get("data", {}).get("attributes", {})

                if attrs.get("status") == "completed":

                    stats = attrs.get("stats", {})

                    positives = (
                        stats.get("malicious", 0)
                        + stats.get("suspicious", 0)
                    )

                    total = sum(stats.values()) if stats else 0

                    if positives > 3:
                        verdict = "malicious"

                    elif positives > 0:
                        verdict = "suspicious"

                    else:
                        verdict = "clean"

                    out = {
                        "verdict": verdict,
                        "positives": positives,
                        "total": total,
                        "raw": aj
                    }

                    CACHE[key] = out

                    return out

            return {
                "verdict": "unknown",
                "error": "timeout",
                "details": "VirusTotal analysis polling timed out",
                "positives": 0,
                "total": 0
            }

        except requests.exceptions.Timeout:

            return {
                "verdict": "unknown",
                "error": "timeout",
                "details": "VirusTotal request timed out",
                "positives": 0,
                "total": 0
            }

        except requests.exceptions.ConnectionError as e:

            return {
                "verdict": "unknown",
                "error": "connection_error",
                "details": str(e),
                "positives": 0,
                "total": 0
            }

        except Exception as e:

            return {
                "verdict": "unknown",
                "error": "unexpected_error",
                "details": str(e),
                "positives": 0,
                "total": 0
            }    