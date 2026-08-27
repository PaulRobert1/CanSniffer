# Civic J2534 CAN Sniffer v2.2 Discovery

<img width="1439" height="911" alt="image" src="https://github.com/user-attachments/assets/2e168416-67a8-4237-b3b4-6bfd2de978e5" />

Receive-only Windows Forms CAN monitor for Honda Civic / J2534 reverse-engineering work.

## v2.2 Discovery changes

### Automatic candidate detector

The sniffer can now learn a quiet baseline and automatically flag CAN changes associated with each experiment marker.

Workflow:

1. Start capture and CSV logging.
2. Press **BASELINE**.
3. Leave the car/controls untouched for several seconds.
4. Select or type a marker, for example `BRAKE_PRESS`.
5. Press **MARK**, then immediately perform the action.
6. The lower **Discovery candidates** pane shows likely CAN ID / byte / bit changes.
7. Candidate records are also written into the CSV as `# CANDIDATE,...` lines.

During BASELINE the app learns which bits are already changing naturally. Those bits are treated as counters/noise and suppressed from the candidate list. This greatly reduces false positives from rolling counters, checksums and continuously changing sensor data.

The default candidate window is **4.0 seconds** and can be changed from 1.0 to 15.0 seconds.

### Confirmed Civic signals tagged automatically

When these appear in a candidate transition, the sniffer adds a known-signal hint:

- `0x164 B0 bit 4 / 0x10` — physical VSA button/request
- `0x1A4 B3 bit 4 / 0x10` — actual latched VSA-disabled state
- `0x294 B1` — instrument illumination/dimmer level
- `0x164 B0 bit 0 / 0x01` — likely illumination/light state
- `0x324 B0` — coolant-temperature-related value; raw-40 C interpretation shown
- `0x158` — vehicle-speed-related frame
- `0x17C` — engine/RPM/status-related frame
- `0x40C` — VIN broadcast

### More experiment presets

The marker drop-down now includes groups for:

- VSA and dimmer
- brake and clutch
- cruise main / set / resume / cancel
- headlights, high beam, indicators, hazards and fog lights
- wipers and washer
- horn, handbrake and reverse
- doors, locks, trunk and windows
- A/C, fan, recirculation and rear defrost
- steering-wheel/audio controls
- throttle-position experiments
- steering-position experiments
- engine start/stop

The marker box remains editable, so any custom experiment name can still be entered.

### Additional bitrate

`33333` and `50000` bit/s options were added for body-bus experiments.

**Important:** selecting 33.333 kbit/s does not electrically reroute the J2534 interface. The normal Civic F-CAN connection is still OBD pins 6/14. To capture a Honda body/B-CAN network, the interface or external wiring must actually be connected/routed to that network and the J2534 driver must support the requested bitrate.

### Candidate output format

Example:

    # MARK,12.000000,"VSA_OFF",2026-08-26T17:00:00+03:00
    # CANDIDATE,12.124000,"VSA_OFF",164,B0,00,10,10,"KNOWN:VSA_BUTTON=PRESS"
    # CANDIDATE,12.248000,"VSA_OFF",1A4,B3,00,10,10,"KNOWN:VSA_DISABLED=YES"

Fields are:

    time, marker, CAN ID, byte, baseline value, new value, changed stable-bit mask, hint

A completely new CAN identifier that appears only after a marker is logged as `NEW_ID`.

## v2.1 features retained

- OpenPort 2.0/Tactrix `SNIFF_MODE = 0x10000000`
- automatic OpenPort DLL detection
- low-latency receive loop
- 50 ms UI refresh
- BASELINE + editable custom marker workflow
- CSV logging
- J2534 read/empty counters
- x86 and x64 build scripts
- no `PassThruWriteMsgs` implementation or calls

## Normal Civic F-CAN setup

- Raw CAN
- 500000 bit/s
- 11-bit identifiers
- Standard OBD CAN pins 6/14

## Recommended mapping procedure

For each control, repeat the experiment at least 3 times. For momentary controls use separate press/release markers when possible.

Suggested sequence:

    BASELINE
    BRAKE_PRESS
    BRAKE_RELEASE
    BRAKE_PRESS
    BRAKE_RELEASE

For stepped controls:

    BASELINE
    DIM_RIGHT
    perform several slow clicks
    DIM_LEFT
    perform several slow clicks

For switches with a latched state:

    BASELINE
    VSA_OFF
    VSA_ON
    VSA_OFF
    VSA_ON

If an action produces no candidates on F-CAN but behaves consistently, it may be local wiring, resistor-ladder input, or traffic on another Honda network such as B-CAN.

## Build

### x86 — recommended for older/clone J2534 drivers

Run:

    build-x86.cmd

Output:

    CivicJ2534CanSniffer-v2.2-x86.exe

### x64

Run:

    build-x64.cmd

Output:

    CivicJ2534CanSniffer-v2.2-x64.exe

The project targets .NET Framework 4.8 and requires no NuGet packages.
