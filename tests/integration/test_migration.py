#!/usr/bin/env python3
"""Test script for Phase 1 migration"""

import subprocess
import sys

def run_test(command, description):
    print(f"\n🧪 {description}")
    print(f"Command: {command}")
    print("-" * 50)
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    print("🚀 Testing Phase 1 Migration")
    
    tests = [
        ("python -m src.main scan .", "Test CLI Navigator (existing)"),
        ("python -m src.main entry-points .", "Test entry point detection (new)"),
        ("python -m src.main entry-points samples/test-projects/", "Test sample app analysis"),
    ]
    
    passed = 0
    for command, description in tests:
        if run_test(command, description):
            passed += 1
    
    print(f"\n🎉 Tests completed: {passed}/{len(tests)} passed")
    
    if passed == len(tests):
        print("✅ Migration successful!")
    else:
        print("⚠️  Some tests failed - check implementation")

if __name__ == '__main__':
    main()
