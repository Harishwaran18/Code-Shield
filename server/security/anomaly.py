"""ML-based session anomaly detection using an Isolation Forest."""

import logging
from pathlib import Path

import numpy as np

try:  # scikit-learn is optional at runtime; the heuristic keeps the platform usable without it.
    import joblib
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when sklearn is absent
    SKLEARN_AVAILABLE = False

logger = logging.getLogger("codeshield.anomaly")

FEATURES = [
    "requests_per_minute",
    "distinct_paths",
    "failed_logins",
    "scans_last_hour",
    "payload_kb",
    "hour_sin",
    "hour_cos",
    "ua_changed",
    "ip_changed",
    "admin_actions",
]


class SessionAnomalyDetector:
    def __init__(self, model_dir: str = "data/models", seed: int = 42) -> None:
        self.model_dir = Path(model_dir)
        self.seed = seed
        self.model = None
        self.means: np.ndarray | None = None
        self.stds: np.ndarray | None = None
        self.low = -0.1
        self.high = 0.1
        self.trained = False

    def load_or_train(self) -> None:
        path = self.model_dir / "anomaly.joblib"
        if SKLEARN_AVAILABLE and path.exists():
            try:
                state = joblib.load(path)
                self.model = state["model"]
                self.means = np.asarray(state["means"])
                self.stds = np.asarray(state["stds"])
                self.low = float(state["low"])
                self.high = float(state["high"])
                self.trained = True
                return
            except Exception:
                logger.warning("could not load anomaly model, retraining", exc_info=True)
        self.train()
        if SKLEARN_AVAILABLE:
            try:
                self.model_dir.mkdir(parents=True, exist_ok=True)
                joblib.dump(
                    {
                        "model": self.model,
                        "means": self.means,
                        "stds": self.stds,
                        "low": self.low,
                        "high": self.high,
                        "features": FEATURES,
                    },
                    path,
                )
            except Exception:
                logger.warning("could not persist anomaly model", exc_info=True)

    def _baseline(self, n: int = 800) -> np.ndarray:
        rng = np.random.default_rng(self.seed)
        rpm = np.clip(rng.lognormal(np.log(18), 0.7, n), 1, 90)
        paths = rng.integers(3, 16, n).astype(float)
        failed = rng.binomial(2, 0.05, n).astype(float)
        scans = rng.poisson(1.2, n).astype(float)
        payload = np.clip(rng.lognormal(np.log(6), 0.9, n), 0, 60)
        hours = rng.integers(0, 24, n).astype(float)
        hour_sin = np.sin(2 * np.pi * hours / 24)
        hour_cos = np.cos(2 * np.pi * hours / 24)
        ua = (rng.random(n) < 0.01).astype(float)
        ip = (rng.random(n) < 0.01).astype(float)
        admin = rng.poisson(2.0, n).astype(float)
        return np.column_stack([rpm, paths, failed, scans, payload, hour_sin, hour_cos, ua, ip, admin])

    def train(self) -> None:
        samples = self._baseline()
        self.means = samples.mean(axis=0)
        self.stds = samples.std(axis=0)
        self.stds[self.stds == 0] = 1.0
        if not SKLEARN_AVAILABLE:
            self.trained = False
            return
        self.model = IsolationForest(
            n_estimators=200, contamination=0.03, random_state=self.seed, n_jobs=1
        )
        self.model.fit(samples)
        scores = self.model.decision_function(samples)
        # Score relative to the baseline median: typical sessions land near 0,
        # only points below the 1st percentile reach 100.
        self.low = float(np.percentile(scores, 1))
        self.high = float(np.percentile(scores, 50))
        self.trained = True

    def score(self, features: dict) -> dict:
        vector = np.array([float(features.get(name, 0.0)) for name in FEATURES])
        if self.trained and self.model is not None and self.means is not None:
            raw = float(self.model.decision_function([vector])[0])
            span = max(self.high - self.low, 1e-9)
            anomaly = float(np.clip((self.high - raw) / span, 0.0, 1.0) * 100)
            deviations = np.abs((vector - self.means) / self.stds)
            drivers = [
                {"feature": name, "deviation": round(float(value), 2)}
                for name, value in sorted(zip(FEATURES, deviations, strict=True), key=lambda item: item[1], reverse=True)[:3]
                if value > 1.0
            ]
            return {"score": round(anomaly, 1), "drivers": drivers, "engine": "isolation_forest"}
        return {"score": self._heuristic(vector), "drivers": [], "engine": "heuristic"}

    @staticmethod
    def _heuristic(vector: np.ndarray) -> float:
        rpm, paths, failed, scans, payload, _, _, ua, ip, admin = vector
        score = 0.0
        score += min(30.0, max(0.0, rpm - 60) / 2)
        score += min(15.0, max(0.0, paths - 15) * 3)
        score += min(20.0, failed * 8)
        score += min(10.0, scans * 3)
        score += min(10.0, max(0.0, payload - 40))
        score += ua * 10 + ip * 15 + min(10.0, admin * 2)
        return round(min(100.0, score), 1)

    def describe(self) -> dict:
        return {
            "engine": "isolation_forest" if self.trained else "heuristic",
            "features": FEATURES,
            "trained": self.trained,
            "model_file": str(self.model_dir / "anomaly.joblib"),
        }
