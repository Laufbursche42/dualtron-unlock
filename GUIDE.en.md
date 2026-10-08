# Guide

> **Important for error reports:** switch on the **Diagnostic log** at the bottom of the page *before* you connect to the scooter. Only then is the full connection handshake captured - and those are exactly the lines we need in a [ticket](https://github.com/Laufbursche42/Laufbursche42/issues) to reproduce a problem.

## What you need
- A DUALTRON / Minimotors e-scooter.
- A phone or computer with **Chrome**, **Edge**, or on iOS **Bluefy**. Safari and Firefox cannot do Web Bluetooth.

## Connecting
1. Turn on Bluetooth and wake the scooter.
2. Tap **Connect** and pick the scooter from the list.
3. If it is not listed, tick **Show all devices** and try again. The real check is the Bluetooth service found (0xFE60), not the advertised name.
4. Once connected, the live-values, speed and settings cards appear. The page immediately polls telemetry and settings.

## Reading live values
The page polls the scooter continuously and it answers with frames. Each tile appears once its value has arrived; a dash just means that value has not come in yet. Below the tiles, **All received frames** lets you follow the raw data per opcode.

## Setting the speed
- **Unlock** sets the legal limit to **Off**, **Lock** sets it to **20 km/h**. The selector sets the limit exactly (Off / 25 / 22 / 20 km/h).
- The **top-speed percent** limits on top of that (clamped to 6 bits, i.e. 0 to 63).
- Important: every write is a read-modify-write. The scooter must have reported its system settings first, otherwise nothing is written. An echo in the log only means the scooter accepted the frame. Only when the limit changes in the live values is the value really active.

## More settings
Max gear lives in the system settings (opcode 0x81, byte 5). Only rows whose value the scooter reports are shown.

## What is deliberately missing
Lock/unlock (immobilizer), light and CCS/PAS exist as opcodes in the protocol, but their exact payload bytes are not present in the decompiled app. So they are not built in here. If you have captured the right frame, you can send it via **Send a raw frame**.

## Advanced settings (engine level)
**Send a raw frame** sends your hex bytes unchanged. **Build a frame** takes an opcode and payload and adds the header, mask (seed) and checksum for you.

## Shortcuts
Copy the link to your home screen, then one tap unlocks or locks directly. On iOS via Bluefy, and the scooter must have been connected normally once before.

## If something does not work
- Cannot connect? Check that the browser supports Web Bluetooth, Bluetooth is on and the scooter is awake. Retry with **Show all devices**.
- Nothing happens after a command? Check the log: if it says "sent" but no "confirmed", the firmware did not acknowledge the frame. If it says "waiting for system settings", no 0x01 frame has arrived yet - wait a moment and retry.
- **Diagnostics: list all devices** in the log area shows every Bluetooth service of a device without writing anything - useful for support.

## Contribute
Want to find out if and how tuning works on your scooter? Test this tool on your own vehicle and open a ticket on [GitHub](https://github.com/Laufbursche42/Laufbursche42/issues) - with your model and what worked (or did not). That way we figure out together what is possible on which model.
