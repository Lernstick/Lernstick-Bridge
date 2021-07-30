import time
import functools

class RetryException(BaseException):
    pass


def retry(func, tries=5, exception=Exception, wait=None):
    """Simple retry decorator"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        for _ in range(tries):
            try:
                return func(*args, **kwargs)
            except exception:
                if wait is not None:
                    time.sleep(wait)
                continue
        raise RetryException(f"Tried {tries} times!")
    return wrapper