#!/usr/bin/env python3
"""
Example demonstrating permission events (FAN_OPEN_PERM, FAN_ACCESS_PERM, FAN_OPEN_EXEC_PERM).

This example shows how to:
1. Monitor permission events on a directory
2. Receive permission events that require a response
3. Send appropriate responses (FAN_ALLOW/FAN_DENY) to allow or deny operations

Note: This requires root privileges to use permission events.
"""

import select
import sys
import os
import time

import pyfanotify as fan


def main():
    if os.geteuid() != 0:
        print("Error: Permission events require root privileges")
        sys.exit(1)

    # Create a test directory
    test_dir = "/tmp/test_fno"
    os.mkdir(test_dir)
    
    print(f"Monitoring permission events on: {test_dir}")
    print("Try accessing files in this directory from another terminal")
    print("Press Ctrl+C to stop")
    
    # Initialize fanotify without FID support (required for permission events)
    fanot = fan.Fanotify(init_fid=False)
    
    # Mark the test directory for permission events
    # We'll monitor open and access permission events
    #perm_events = fan.FAN_OPEN_PERM | fan.FAN_ACCESS_PERM | fan.FAN_OPEN_EXEC_PERM
    #perm_events = fan.FAN_ACCESS_PERM
    perm_events = fan.FAN_OPEN| fan.FAN_ACCESS
    print("1")
    fanot.mark(test_dir, ev_types=perm_events, is_type='fs')
    print("2")
    fanot.start()
    print("3")

    # Create a client to receive events
    # pass_fd=True is required to get file descriptors for permission responses
    cli = fan.FanotifyClient(fanot, path_pattern='*', pass_fd=True)
    print("4")
    
    poll = select.poll()
    print("5")
    poll.register(cli.sock.fileno(), select.POLLIN)
    print("6")
    
    try:
        while poll.poll():
            print("7")
            for event in cli.get_events():
                print(event)
                event_str = fan.evt_to_str(event.ev_types)
                path = event.path[0].decode() if event.path else "unknown"
                
                print(f"Permission event: {event_str}")
                print(f"  PID: {event.pid}")
                print(f"  Path: {path}")
                print(f"  FD: {event.fd}")
                
                # Decide whether to allow or deny the operation
                # For this example, we'll allow all operations
                # You could implement custom logic here
                response_action = fan.FAN_ALLOW
                
                if event.ev_types & fan.FAN_ALL_PERM_EVENTS:
                    try:
                        # Send response to allow the operation
                        cli.response(event.fd, response_action)
                        print(f"  Response: ALLOWED")
                    except Exception as e:
                        print(f"  Error sending response: {e}")
                    finally:
                        # Always close the file descriptor
                        os.close(event.fd)
                
                print()
                
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        cli.close()
        fanot.stop()
        
        # Clean up test directory
        try:
            os.rmdir(test_dir)
        except OSError:
            pass


if __name__ == '__main__':
    main()
