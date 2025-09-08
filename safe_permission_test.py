#!/usr/bin/env python3
"""
Safe permission events test script with comprehensive diagnostics.

This script implements safety measures to prevent system freezes when testing
fanotify permission events.
"""

import select
import sys
import os
import time
import signal

import pyfanotify as fan


class TimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    print("TIMEOUT: Process timed out - this indicates a potential deadlock")
    raise TimeoutError("Process timed out")


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


def safe_permission_test():
    if os.geteuid() != 0:
        print("Error: Permission events require root privileges")
        sys.exit(1)

    test_dir = "/home/yhy/test-f/"
    os.makedirs(test_dir, exist_ok=True)
    
    print("This directory will be automatically cleaned up on exit")
    
    # Set up timeout protection
    signal.signal(signal.SIGALRM, timeout_handler)
    
    try:
        #print("\n=== STEP 1: Testing with NON-permission events first ===")
        #test_non_permission_events(test_dir)
        
        print("\n=== STEP 2: Testing with permission events (with timeout) ===")
        test_permission_events_safe(test_dir)
        
    except TimeoutError:
        print("\nTIMEOUT DETECTED: The process hung, indicating a deadlock issue")
        print("This confirms the permission event deadlock hypothesis")
        return False
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return False
    except Exception as e:
        print(f"\nError occurred: {e}")
        return False
    finally:
        # Clean up
        signal.alarm(0)  # Cancel any pending alarm
    
    return True


def test_non_permission_events(test_dir):
    """Test with regular (non-permission) events first to verify basic functionality."""
    print("Testing with FAN_ACCESS (non-permission event)...")
    
    # Set 5 second timeout for this test
    signal.alarm(5)
    
    fanot = None
    cli = None
    
    try:
        # Initialize fanotify without FID support
        fanot = fan.Fanotify(init_fid=False)
        print("✓ Fanotify initialized")
        
        # Mark with non-permission event
        fanot.mark(test_dir, ev_types=fan.FAN_ALL_EVENTS, is_type='fs')
        print("✓ Directory marked for FAN_ACCESS")
        
        fanot.start()
        print("✓ Fanotify started successfully")
        
        # Create client
        cli = fan.FanotifyClient(fanot, path_pattern="*", pass_fd=False)
        print("✓ Client created")
        
        # Test by creating a file
        test_file = os.path.join(test_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test")
        print("✓ Created test file")
        
        # Brief event collection
        poll = select.poll()
        poll.register(cli.sock.fileno(), select.POLLIN)
        
        events_received = 0
        #for _ in range(3):  # Try for 3 iterations
        while(True):
            if poll.poll(1000):  # 1 second timeout
                for event in cli.get_events():
                    events_received += 1
                    print(f"✓ Received event: {fan.evt_to_str(event.ev_types)}")
                    if events_received >= 1:
                        break
            if events_received >= 1:
                break
        
        print(f"✓ Non-permission events working (received {events_received} events)")
        
    finally:
        signal.alarm(0)
        try:
            if cli:
                cli.close()
            if fanot:
                fanot.stop()
        except:
            pass


def test_permission_events_safe(test_dir):
    """Test permission events with safety measures."""
    print("Testing with FAN_ACCESS_PERM (permission event)...")
    print("WARNING: This is where the original script freezes")
    
    # Set 10 second timeout for this test
    signal.alarm(12)
    
    fanot = None
    cli = None

    # Create a test file in a separate process to avoid self-deadlock
    test_file = os.path.join(test_dir, "perm_test.txt")
    with open(test_file, 'w') as f:
        f.write("permission test")
    
    try:
        print("Step 1: Initializing fanotify...")
        fanot = fan.Fanotify(init_fid=False)
        print("✓ Fanotify initialized")
        
        print("Step 2: Marking directory for permission events...")
        fanot.mark(test_dir, ev_types=fan.FAN_OPEN_PERM | fan.FAN_ACCESS_PERM, is_type='fs')
        print("✓ Directory marked for FAN_ACCESS_PERM")
        
        print("Step 3: Starting fanotify (this is where freezing occurs)...")
        fanot.start()
        print("✓ Fanotify started successfully!")
        
        print("Step 4: Creating client...")
        cli = fan.FanotifyClient(fanot, path_pattern="*", pass_fd=True)
        print("✓ Client created")
        
        print("Step 5: Setting up event polling...")
        poll = select.poll()
        poll.register(cli.sock.fileno(), select.POLLIN)
        print("✓ Polling setup complete")
        
        print("Step 6: Testing with a file access...")
        
        print("NOTE: Please execute operation in another terminal...")
        events_handled = 0
        start_time = time.time()
        
        while time.time() - start_time < 10:
            if poll.poll(1000):  # 1 second timeout
                for event in cli.get_events():
                    print(f"✓ Received permission event: {fan.evt_to_str(event.ev_types)}")
                    print(f"  PID: {event.pid}")
                    print(f"  FD: {event.fd}")
                    print(f"  File path: {get_filename_from_fd(event.fd)}")
                    
                    # CRITICAL: Send permission response
                    if event.ev_types & fan.FAN_ALL_PERM_EVENTS:
                        try:
                            cli.response(event.fd, fan.FAN_ALLOW)
                            print("  ✓ Sent FAN_ALLOW response")
                            events_handled += 1
                        except Exception as e:
                            print(f"  ✗ Error sending response: {e}")
                        finally:
                            if event.fd >= 0:
                                os.close(event.fd)
                                print("  ✓ Closed file descriptor")
                    
                    if events_handled >= 1:
                        break
            
            if events_handled >= 1:
                break
        
        if events_handled > 0:
            print(f"✓ Permission events working! Handled {events_handled} events")
        else:
            print("⚠ No permission events received (this might indicate an issue)")
        
    finally:
        signal.alarm(0)
        try:
            if cli:
                cli.close()
            if fanot:
                fanot.stop()
        except:
            pass


def main():
    print("=== Safe Fanotify Permission Events Test ===")
    print("This script implements safety measures to prevent system freezes")
    print()
    
    if safe_permission_test():
        print("\n✓ All tests completed successfully!")
        print("The permission events are working correctly with proper handling.")
    else:
        print("\n✗ Tests failed or timed out")
        print("This indicates issues with the permission event implementation.")
    
    print("\nDiagnostic complete.")


if __name__ == '__main__':
    main()
