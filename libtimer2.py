import time

class Timer:
    def __init__(self) -> None:
        self.ctime = 0.0
        self.reset()
    def reset(self) -> float:
        self.ctime = time.monotonic()
        return self.ctime
    def subtract(self, value: float) -> float:
        self.ctime -= value
        return self.ctime
    def get_time(self) -> float:
        return (time.monotonic()-self.ctime)