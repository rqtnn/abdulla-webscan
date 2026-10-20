"""Independent scanner batch scheduling; dependency stages stay ordered."""
import concurrent.futures


def run_batch(runner, jobs, mode, workers):
    if mode == "sequential":
        return [runner.execute(job) for job in jobs]
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(runner.execute, job) for job in jobs]
    try:
        # Results retain input order even if execution finishes in a different order.
        return [future.result() for future in futures]
    except KeyboardInterrupt:
        runner.cancel()
        return [future.result() for future in futures]
    finally:
        pool.shutdown(wait=True)


