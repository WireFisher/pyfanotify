#!/usr/bin/env python3
"""
Test script to demonstrate the fanotify permission events deadlock.

This script proves that the deadlock occurs due to self-monitoring during
the fanotify process initialization.
"""

import os
import sys
import time
import signal
import multiprocessing as mp
from contextlib import contextmanager

import pyfanotify as fan


class TimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutError("Operation timed out")

def get_filename_from_fd(fd):
    """Get the filename from a file descriptor."""
    try:
        # Use /proc/self/fd/ to resolve the file path
        fd_path = f"/proc/self/fd/{fd}"
        if os.path.exists(fd_path):
            return os.readlink(fd_path)
        else:
            return f"<unknown fd={fd}>"
    except Exception as e:
        return f"<error reading fd={fd}: {e}>"

@contextmanager
def timeout(seconds):
    """Context manager for timeout operations."""
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


def test_separate_process_approach():
    """Test using separate processes to avoid self-deadlock."""
    print("\n=== Testing Separate Process Approach ===")
    
    def monitor_process(test_dir):
        """Run fanotify monitoring in a separate process."""
        try:
            fanot = fan.Fanotify(init_fid=False)
            fanot.mark(test_dir, ev_types=fan.FAN_OPEN_PERM | fan.FAN_ACCESS_PERM, is_type='fs')
            fanot.start()
            
            # Create client to handle events
            cli = fan.FanotifyClient(fanot, path_pattern='*', pass_fd=True)
            
            # Simple event loop for a few seconds
            import select
            poll = select.poll()
            poll.register(cli.sock.fileno(), select.POLLIN)
            
            start_time = time.time()
            while time.time() - start_time < 5:  # Run for 5 seconds
                if poll.poll(1000):  # 1 second timeout
                    for event in cli.get_events():
                        print(f"✓ Received permission event: {fan.evt_to_str(event.ev_types)}")
                        print(f"  PID: {event.pid}")
                        print(f"  FD: {event.fd}")
                        print(f"  File path: {get_filename_from_fd(event.fd)}")
                        # Auto-allow all events
                        if event.ev_types & fan.FAN_ALL_PERM_EVENTS:
                            cli.response(event.fd, fan.FAN_ALLOW)
            
            cli.close()
            fanot.stop()
            return True
            
        except Exception as e:
            print(f"Monitor process error: {e}")
            return False
    
    if os.geteuid() != 0:
        print("Error: Permission events require root privileges")
        return False
    
    test_dir = "/home/yhy/test-f/"
    os.makedirs(test_dir, exist_ok=True)
    
    process = None
    try:
        print("1. Starting monitoring in separate process...")
        process = mp.Process(target=monitor_process, args=(test_dir,))
        process.start()
        
        # Give it time to start
        time.sleep(2)
        
        if process.is_alive():
            print("2. ✓ Monitoring process started successfully!")
            print("3. Waiting for process to complete...")
            process.join(timeout=10)
            
            if process.exitcode == 0:
                print("4. ✓ Separate process approach worked!")
                return True
            else:
                print(f"4. ✗ Process failed with exit code: {process.exitcode}")
                return False
        else:
            print("2. ✗ Monitoring process failed to start")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    finally:
        try:
            os.rmdir(test_dir)
        except:
            pass
        try:
            if process and process.is_alive():
                process.terminate()
                process.join(timeout=5)
        except:
            pass


def main():
    print("Fanotify Permission Events Deadlock Test")
    print("=" * 50)
    
    results = []
    
    # Test 3: Separate process approach (should work)
    results.append(("Separate Process", test_separate_process_approach()))
    
    print("\n" + "=" * 50)
    print("RESULTS SUMMARY:")
    print("=" * 50)
    
    for test_name, success in results:
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"{test_name:25} {status}")


if __name__ == '__main__':
    main()
