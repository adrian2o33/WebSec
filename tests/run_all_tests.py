import unittest
import sys
import os

# Colors for CLI output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def run_tests():
    # Setup test discovery
    test_dir = os.path.dirname(__file__)
    print(f"{Colors.HEADER}{Colors.BOLD}=== WebSecScanner Enterprise Test Suite ==={Colors.ENDC}")
    print(f"{Colors.OKCYAN}Discovering tests in {test_dir}...{Colors.ENDC}\n")

    loader = unittest.TestLoader()
    suite = loader.discover(test_dir, pattern='test_*.py')

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Output Summary
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== Final Test Report ==={Colors.ENDC}")
    total_tests = result.testsRun
    failed_tests = len(result.failures)
    errored_tests = len(result.errors)
    passed_tests = total_tests - (failed_tests + errored_tests)

    if result.wasSuccessful():
        print(f"{Colors.OKGREEN}{Colors.BOLD}[PASSED] ALL {total_tests} TESTS PASSED SUCCESSFULLY!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}The WebSecScanner is 100% healthy, accurate, and ready for deployment.{Colors.ENDC}")
        sys.exit(0)
    else:
        print(f"{Colors.FAIL}{Colors.BOLD}[FAILED] TEST SUITE FAILED{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Passed: {passed_tests}{Colors.ENDC}")
        print(f"{Colors.FAIL}Failed: {failed_tests}{Colors.ENDC}")
        print(f"{Colors.WARNING}Errors: {errored_tests}{Colors.ENDC}")
        sys.exit(1)

if __name__ == '__main__':
    run_tests()
