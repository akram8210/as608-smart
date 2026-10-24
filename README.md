# AS608 Smart v1.1 — classroom test build

MakeCode Blocks extension for BBC micro:bit V2 and AS608 fingerprint scanner. English and Swedish labels.

## Changes since v1.0
- No finger (`0x02`) is different from poor image (`-5`), no match (`-9`), and UART failure (`-2`). Only confirmed `-9` fires the rejected event.
- Automatic events run on independent fibers so `play tone ... until done` does not hold up polling.
- Two consecutive no-finger readings are required before another placement can trigger an event.
- Lockout is **disabled by default**; teachers can explicitly configure it in advanced blocks.
- Stop/restart of background scanning invalidates the previous loop.
- Existing bounded UART frame receiver retained.

## Test (Blocks)
1. `on start`: Connect scanner RX to P13, TX to P14, **do nothing**; pause 2000 ms; start automatic fingerprint scanning.
2. `on fingerprint recognized`: show check icon; play tone 262 Hz for 1 beat.
3. `on fingerprint rejected`: show X icon; play tone 131 Hz for 1/2 beat.
4. `on scanner communication error`: show a distinct symbol or count errors (avoid long animations).
5. Test registered and unregistered fingers, remove finger between trials, and test with no finger for 5 minutes.

Do not run manual Scan finger or enrollment concurrently with automatic scanning. Stop automatic scanning before using manual commands. No motor should be connected for initial verification.

## Updating GitHub
Replace `main.ts`, `pxt.json`, `README.md` and `_locales` in your repository. In MakeCode remove and re-add the extension or create a new test project if the previous code is cached.

## Status
Source-level changes only. Not compiled with the MakeCode compiler or hardware-tested here. A successful result on your physical AS608 and micro:bit V2 is required before classroom deployment. This is an educational prototype, not a security-rated lock.
