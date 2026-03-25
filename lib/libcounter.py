import time

class Counter:
    def __init__(self) -> None:
        self.count = 0
        self.ctime = 0.0
        self.reset()

    def reset(self) -> int:
        self.count = 0
        self.ctime = time.monotonic()
        return self.count

    def beat(self) -> "Counter":
        self.count += 1
        return self

    def get_rate(self) -> float:
        elapsed = time.monotonic() - self.ctime
        return self.count / elapsed if elapsed > 0 else 0.0