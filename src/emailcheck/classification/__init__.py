"""Passive datasets and the matchers that read them.

Nothing here performs I/O at import time. A caller loads a dataset directory
explicitly, so a program that never classifies never reads a file, and a test
never depends on what happens to be on disk.
"""
