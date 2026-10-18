# FIXTURE for aegis emulate tests (tests/test_emulate.py).
# Benign sample: the emulator should report no pattern signals here.
import math


def add(a, b):
    return a + b


def circle_area(radius):
    return math.pi * radius * radius


if __name__ == "__main__":
    print(add(2, 3))
