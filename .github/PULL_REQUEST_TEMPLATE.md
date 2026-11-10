## Summary
Explain what changed and why.

## Checks Run
- [ ] `cd android && ./gradlew testDebugUnitTest --no-daemon`
- [ ] `cd macos && ./build.sh`
- [ ] `python3 -m unittest macos/test_claude_processor.py && python3 macos/claude_processor.py --audit`

## Privacy Check
- [ ] Confirmed no device serial numbers, personal Wi-Fi SSIDs, local LAN IPs, test payloads, or API keys are included in this PR.
