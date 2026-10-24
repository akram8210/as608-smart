# AS608 Smart Fingerprint v1.0 — source release (not hardware-verified)

## Capabilities
- Swedish/English MakeCode block labels, original enrollment/search/delete blocks retained.
- Full-frame UART timeout, ACK address/length/checksum verification.
- Automatic polling and recognized/rejected/communication-error event handlers.
- Last fingerprint ID, counts, configurable rejected-attempt lockout.
- Standard MakeCode LED, sound, servo, motor-driver, relay blocks can be placed inside events. No unsafe direct motor-driving block is provided.

## Important limitations
- **Not compiled against the MakeCode toolchain and not tested with physical AS608**; this is a source-level implementation, not a certified working extension.
- Avoid calling other fingerprint blocks while automatic scanning is running: the original API is not globally serialized. Stop automatic scanning before enrollment, deletion or manual searches.
- Timeout does not reset an electrically frozen sensor. An AS608 running at 3.3 V must be checked against the exact module voltage/current requirements and breakout power rails.
- Rejection events are debounced until a no-finger scan occurs. A failed scan can be a poor image, not an unauthorized user.
- This is a classroom prototype, not a security-rated door lock. Do not use for actual access control without hardware validation.

## Block test
On start: connect scanner RX P13, TX P14, do nothing; then register on recognized (show check), on rejected (show X), on communication error (show sad face); then start automatic fingerprint scanning. Connect an LED/buzzer/servo through the corresponding standard MakeCode blocks in each handler after verifying external wiring and motor power.

## Installation
Unzip files to a public GitHub repository and add it through MakeCode Extensions using the repository URL. The ZIP itself is source code and is not a .hex firmware.
