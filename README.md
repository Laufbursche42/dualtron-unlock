# Laufbursche DUALTRON unlock

A static web page that talks to DUALTRON / Minimotors e-scooters over Web Bluetooth. Connect, read the live values and - straight from the browser - set the legal speed limit, the top-speed percentage and the maximum gear. Nothing to install: no app store, no signing, no developer account. It runs in **Bluefy** on iOS and in **Chrome** or **Edge** on Android or desktop.

> **This is a feasibility study - the writes are sent, their effect on hardware is unconfirmed.** It exists to show what Minimotors' Bluetooth protocol makes possible, not to be a finished product; the protocol was reconstructed from the official app (`com.minimotors.escooter`, FastBLE) and is documented byte for byte. One generic profile covers every DUALTRON model (model names come from the vendor server, not the app) and there is no real BLE authentication - the per-packet obfuscation seed is sent in cleartext, so any client that knows the frame can read and write. **Reading works and is fully proven:** telemetry (battery, speed, mileage, gear, fault), the system page (legal limit, voltage, wheel size, max gear) and the controller/max-speed page are decoded and shown. The writes - legal limit (opcode `0x81`, byte 0), max gear (`0x81`, byte 5) and top-speed percent (`0x82`, byte 2) - are read-modify-write: the page resends the whole settings payload with a single proven field changed, so nothing else is disturbed. Whether the firmware accepts them without an owner/password token, and whether a limit of *off* truly lifts the cap, sits in the controller and cannot be proven from the app: it must be tested on the device. Commands whose exact bytes are **not** in the decompiled app (immobilizer lock/unlock, light/RGB, CCS/PAS) are deliberately **not** implemented here - use the expert raw sender if you have captured the frame. Error-free operation is not promised and there is no warranty of any kind. Whatever you do with it, you do at your own risk - read the [Legal](#legal) section before you connect a scooter.

**Open the web app: [laufbursche42.github.io/dualtron-unlock](https://laufbursche42.github.io/dualtron-unlock/)**

Or run it yourself, no build step and no dependencies: clone the repo and serve the folder over a local HTTP server. Opening `index.html` directly as a `file://` URL will not work, the page fetches its own documents and browsers block that over `file://`.

```
git clone https://github.com/Laufbursche42/dualtron-unlock.git
cd dualtron-unlock
python -m http.server 8000
```

Any static server works. With Node installed, this does the same job:

```
npx serve .
```

Then open the printed address in a browser that supports Web Bluetooth.

**Guide: [Deutsch](GUIDE.de.md) | [English](GUIDE.en.md)** covers everything step by step, from connecting to the first send.

## What it does

- **Live values** - legal limit, top-speed percent, speed, battery, voltage, gear, max gear, trip and total mileage, current, power, range, wheel size, fault, controller type and the device max speed.
- **Speed** - an unlock/lock toggle (legal limit off vs 20 km/h), an explicit limit selector (off / 25 / 22 / 20 km/h) and a top-speed percent set. Writes the `0x81` system register via read-modify-write.
- **More settings** - maximum gear, via `0x81` byte 5.
- **Expert** - send a raw frame verbatim, or build one from an opcode plus payload (the header, obfuscation mask and checksum are added for you).
- **Shortcut** - a home-screen link that unlocks or locks in a single tap.

## Protocol (proven)

- Service `0xFE60`, write characteristic `0xFE61`, notify characteristic `0xFE62`. No pairing, no real auth.
- Frame (16 bytes): `AA | seed(0..9) | opcode | 11 payload bytes each (value+secret) | checksum = sum(bytes[1..13]) & 0xFF | EE`, with `secret = ((((seed+33)*73) ^ 169) & 249)` carried in cleartext via the seed.
- RX read opcodes `0x00` telemetry, `0x01` system, `0x02` user, `0x05` controller/max-speed. TX write opcodes `0x81` system (legal cap byte 0 bits 6-7, max gear byte 5 bits 5-7), `0x82` user (top-speed percent byte 2 bits 0-5).

## Honesty

Device-untested by design - you test on your own scooter, which is exactly the point of a public tool. An echo in the log means the scooter **accepted** the frame; only the setting re-appearing in the live values with the new value proves it actually took effect. The lock/unlock, light and CCS/PAS write opcodes exist in the app but their exact payload bytes were not extracted, so they are not implemented - they are gated, not guessed.

## Legal

License: PolyForm Noncommercial, see [License](LICENSE.md). Privacy: nothing leaves your device, see [Privacy](PRIVACY.md). Trademarks: DUALTRON and Minimotors are trademarks of their respective owner, this project is independent, see [Trademarks](TRADEMARKS.md).

Source: https://github.com/Laufbursche42/dualtron-unlock
