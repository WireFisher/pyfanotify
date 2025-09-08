#!/usr/bin/env python3
"""
Simple test to verify permission events support is working.
"""

import pyfanotify as fan

def test_permission_events_constants():
    """Test that permission event constants are available."""
    print("Testing permission event constants...")
    
    # Test that constants exist and have non-zero values
    assert hasattr(fan, 'FAN_OPEN_PERM'), "FAN_OPEN_PERM not found"
    assert hasattr(fan, 'FAN_ACCESS_PERM'), "FAN_ACCESS_PERM not found"
    assert hasattr(fan, 'FAN_OPEN_EXEC_PERM'), "FAN_OPEN_EXEC_PERM not found"
    
    assert fan.FAN_OPEN_PERM != 0, "FAN_OPEN_PERM is zero"
    assert fan.FAN_ACCESS_PERM != 0, "FAN_ACCESS_PERM is zero"
    assert fan.FAN_OPEN_EXEC_PERM != 0, "FAN_OPEN_EXEC_PERM is zero"
    
    print(f"  FAN_OPEN_PERM = {fan.FAN_OPEN_PERM:#x}")
    print(f"  FAN_ACCESS_PERM = {fan.FAN_ACCESS_PERM:#x}")
    print(f"  FAN_OPEN_EXEC_PERM = {fan.FAN_OPEN_EXEC_PERM:#x}")
    
    # Test response constants
    assert hasattr(fan, 'FAN_ALLOW'), "FAN_ALLOW not found"
    assert hasattr(fan, 'FAN_DENY'), "FAN_DENY not found"
    assert hasattr(fan, 'FAN_AUDIT'), "FAN_AUDIT not found"
    
    print(f"  FAN_ALLOW = {fan.FAN_ALLOW:#x}")
    print(f"  FAN_DENY = {fan.FAN_DENY:#x}")
    print(f"  FAN_AUDIT = {fan.FAN_AUDIT:#x}")
    
    print("✓ Permission event constants test passed")

def test_permission_events_in_masks():
    """Test that permission events are included in event masks."""
    print("\nTesting permission events in event masks...")
    
    # Test FAN_ALL_PERM_EVENTS includes all permission events
    expected_perm = fan.FAN_OPEN_PERM | fan.FAN_ACCESS_PERM | fan.FAN_OPEN_EXEC_PERM
    assert fan.FAN_ALL_PERM_EVENTS == expected_perm, f"FAN_ALL_PERM_EVENTS mismatch: {fan.FAN_ALL_PERM_EVENTS:#x} != {expected_perm:#x}"
    
    print(f"  FAN_ALL_PERM_EVENTS = {fan.FAN_ALL_PERM_EVENTS:#x}")
    
    print("✓ Permission events mask test passed")

def test_evt_to_str():
    """Test that evt_to_str works with permission events."""
    print("\nTesting evt_to_str with permission events...")
    
    # Test individual permission events
    assert 'open_perm' in fan.evt_to_str(fan.FAN_OPEN_PERM)
    assert 'access_perm' in fan.evt_to_str(fan.FAN_ACCESS_PERM)
    assert 'open_exec_perm' in fan.evt_to_str(fan.FAN_OPEN_EXEC_PERM)
    
    # Test combined events
    combined = fan.FAN_OPEN_PERM | fan.FAN_ACCESS_PERM
    result = fan.evt_to_str(combined)
    assert 'open_perm' in result and 'access_perm' in result
    
    print(f"  FAN_OPEN_PERM -> '{fan.evt_to_str(fan.FAN_OPEN_PERM)}'")
    print(f"  FAN_ACCESS_PERM -> '{fan.evt_to_str(fan.FAN_ACCESS_PERM)}'")
    print(f"  FAN_OPEN_EXEC_PERM -> '{fan.evt_to_str(fan.FAN_OPEN_EXEC_PERM)}'")
    print(f"  Combined -> '{result}'")
    
    print("✓ evt_to_str test passed")

def test_response_function():
    """Test that response function exists and validates input."""
    print("\nTesting response function...")
    
    assert hasattr(fan, 'response'), "response function not found"
    assert callable(fan.response), "response is not callable"
    
    # Test invalid response value
    try:
        fan.response(-1, 999)  # Invalid fd and response
        assert False, "Should have raised ValueError for invalid response"
    except ValueError as e:
        assert "Invalid response" in str(e)
        print(f"  ✓ Correctly rejected invalid response: {e}")
    except OSError:
        # This is also acceptable since we're using an invalid fd
        print("  ✓ Got OSError for invalid fd (expected)")
    
    print("✓ Response function test passed")

def test_fanotify_creation():
    """Test that Fanotify can be created without FID for permission events."""
    print("\nTesting Fanotify creation for permission events...")
    
    try:
        # This should work - creating without FID support
        fanot = fan.Fanotify(init_fid=False)
        print("  ✓ Created Fanotify without FID support")
        
        # Test that permission events are rejected with FID
        try:
            fanot_fid = fan.Fanotify(init_fid=True)
            # This should fail when trying to mark with permission events
            try:
                fanot_fid.mark('/tmp', ev_types=fan.FAN_OPEN_PERM)
                assert False, "Should have raised ValueError for PERM events with FID"
            except ValueError as e:
                assert "PERM events are not allowed with FID report" in str(e)
                print(f"  ✓ Correctly rejected PERM events with FID: {e}")
            finally:
                fanot_fid.stop()
        except OSError:
            # Might fail if not running as root, that's OK for this test
            print("  ✓ FID test skipped (likely not running as root)")
        
        fanot.stop()
        
    except OSError as e:
        if "No fanotify" in str(e) or "Operation not permitted" in str(e):
            print(f"  ⚠ Skipped (not running as root or no fanotify support): {e}")
        else:
            raise
    
    print("✓ Fanotify creation test passed")

def main():
    print("Testing pyfanotify permission events support...\n")
    
    test_permission_events_constants()
    test_permission_events_in_masks()
    test_evt_to_str()
    test_response_function()
    test_fanotify_creation()
    
    print("\n🎉 All tests passed! Permission events support is working correctly.")
    print("\nNote: To fully test permission events functionality, run examples/permission_events.py as root.")

if __name__ == '__main__':
    main()
