# Field recordings

Both recordings are from a Google Voice web client (a desktop browser) calling a US MVNO line on a Pixel 9 (Wi-Fi calling). The downlink audio was recorded on the phone by Bageo, 16 kHz mono, and contains only modem test tones.

## 2026-11-23-gv-vowifi-narrow-rx.wav

Sent: `modem-wav gen --gear narrow --frames 100 --seed 7 --lead-ms 15000 --tail-ms 2000 --level-dbfs -18 --repeat-preamble-every 10`

Result: 5/100 frames before the change; 12/100 frames after adding receive-side compensation.

## 2026-11-23-gv-vowifi-concat-rx.wav

Sent: `modem-wav concat -o call.wav silence:15 probe narrow:24:seed=7:repeat=8 silence:1 wide:30:seed=8:repeat=10 silence:1 robust:18:seed=9:repeat=6 silence:1`

Recording time = sent-file time − 6.771 s (the preamble of the probe segment is at 8.229 s in the recording).

| Segment | Analysis parameters | Result |
|---|---|---|
| Channel probe | `analyze-probe` | Single-tone gain: about +6 dB at 500 Hz, about −8 dB at 2 kHz, about −14 dB at 3 kHz |
| narrow | `--frames 24 --seed 7 --repeat-preamble-every 8 --start-s 19.63 --end-s 29.51` | 3/24 frames, pre-FEC bit error rate 20.28% |
| wide | `--frames 30 --seed 8 --repeat-preamble-every 10 --start-s 29.51 --end-s 36.51` | 0/30 frames, 32.73% |
| robust | `--frames 18 --seed 9 --repeat-preamble-every 6 --start-s 36.51 --end-s 61.75` | 17/18 frames, 2.65% |

## speech-comparison

Five short listening samples generated with `tools/modem-wav`. They are synthetic modem output written straight to a file: nothing here was sent over a call and there is no human voice in them. They let you hear a data burst in the older tone gears and in the speech-like gear.

| File | What you hear |
|---|---|
| `1-before-narrow1200.wav` | The Narrowband1200 tone gear |
| `2-before-robust300.wav` | The Robust300 tone gear |
| `3-after-speech300-continuous.wav` | Speech300, frames back to back, the default (male) timbre |
| `4-after-speech300-conversation.wav` | Speech300 in bursts with quiet comfort-noise pauses in between, like turns in a conversation |
| `5-after-speech300-female.wav` | Speech300 with the female timbre (`--voice female`) |

All are 16 kHz, mono, 16-bit.
