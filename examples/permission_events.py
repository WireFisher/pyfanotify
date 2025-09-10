#!/usr/bin/env python3
import select
import sys
import os
import time

import pyfanotify as fan
import multiprocessing as mp


def run():
    if os.geteuid() != 0:
        print("Error: Permission events require root privileges")
        sys.exit(1)

    # Create a test directory
    test_dir = "/home"
    
    print(f"Monitoring permission events on: {test_dir}")
    print("Try accessing files in this directory from another terminal")
    print("Press Ctrl+C to stop")
    
    # Initialize fanotify without FID support (required for permission events)
    fanot = fan.Fanotify(init_fid=False)
    
    # Mark the test directory for permission events
    # We'll monitor open and access permission events
    perm_events = fan.FAN_OPEN_PERM | fan.FAN_ACCESS_PERM | fan.FAN_OPEN_EXEC_PERM
    fanot.mark(test_dir, ev_types=perm_events, is_type='fs')
    fanot.start()

    # Create a client to receive events
    # pass_fd=True is required to get file descriptors for permission responses
    cli = fan.FanotifyClient(fanot, path_pattern='*', pass_fd=True)
    
    poll = select.poll()
    poll.register(cli.sock.fileno(), select.POLLIN)
    
    try:
        while poll.poll():
            for event in cli.get_events():
                event_str = fan.evt_to_str(event.ev_types)
                # Get path from file descriptor instead of event struct
                try:
                    path = os.readlink(f"/proc/self/fd/{event.fd}")
                except (OSError, FileNotFoundError):
                    path = "unknown"
                
                print(f"Permission event: {event_str}")
                print(f"  PID: {event.pid}")
                print(f"  Path: {path}")
                print(f"  FD: {event.fd}")
                print(f"  Original FD: {event.original_fd}")
                
                # Decide whether to allow or deny the operation
                # For this example, we'll allow all operations
                # You could implement custom logic here
                response_action = fan.FAN_ALLOW
                
                if event.ev_types & fan.FAN_ALL_PERM_EVENTS:
                    try:
                        # Send response to allow the operation
                        cli.response(event.original_fd, response_action)
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

def run_monitor_in_seperate_process():
    """
    We need to run the monitor in a seperate process to avoid deadlock.
    """
    process = None
    try:
        process = mp.Process(target=run, args=())
        process.start()
        
        # Give it time to start
        time.sleep(2)
        
        if process.is_alive():
            process.join(timeout=None)
            
            if process.exitcode == 0:
                print("✓ Separate process approach worked!")
            else:
                print(f"✗ Process failed with exit code: {process.exitcode}")
        else:
            print("✗ Monitoring process failed to start")
            
    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        try:
            if process and process.is_alive():
                process.terminate()
                process.join(timeout=5)
        except:
            pass

if __name__ == '__main__':
    run_monitor_in_seperate_process()
