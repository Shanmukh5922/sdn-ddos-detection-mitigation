__all__ = ["ThresholdDetector", "EntropyDetector", "RandomForestDetector"]


def __getattr__(name):
    if name == "ThresholdDetector":
        from .threshold import ThresholdDetector

        return ThresholdDetector
    if name == "EntropyDetector":
        from .entropy import EntropyDetector

        return EntropyDetector
    if name == "RandomForestDetector":
        from .random_forest import RandomForestDetector

        return RandomForestDetector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
