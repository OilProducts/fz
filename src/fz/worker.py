import logging
from .__main__ import Fuzzer

def worker(args, result_queue=None):
    if not logging.getLogger().hasHandlers():
        level = logging.DEBUG if getattr(args, "debug", False) else logging.INFO
        logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")
    fuzzer = Fuzzer(args.corpus_dir, args.output_bytes)
    fuzzer._fuzz_loop(args, result_queue)
