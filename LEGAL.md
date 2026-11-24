# Legal Disclaimer & Usage Notice

This document sets out general disclaimers, operational risks, and usage notices for DialCrypt. Nothing here is legal advice; consult a qualified lawyer if you have questions about applicable law. License terms are in [`LICENSE`](LICENSE) (`GPL-3.0-only`).

## 1. Provided "AS IS" & No Hosted Service

- **Provided "AS IS":** DialCrypt is a pre-alpha research prototype and has not been audited by any third party. To the maximum extent permitted by applicable law, it is provided "AS IS" without warranties of any kind (express, implied, or statutory, including merchantability, fitness for a particular purpose, availability, or regulatory compliance), and without any guarantee of confidentiality, integrity, or availability. Neither the author (**h4lo-void**) nor any contributor is liable for any loss arising from installing, configuring, or using the software, including:
  - irrecoverable destruction of keys and vault data, whether caused by entering a duress PIN (which wipes the keys and the vault by design) or by reaching the wrong-PIN limit (five wrong PINs permanently disable the vault);
  - loss of warranty, bricked devices, or data wipes caused by unlocking the bootloader, rooting, installing Magisk modules, or relocking the bootloader;
  - carrier charges, roaming fees, and suspension or termination of your phone number or service;
  - failed calls, dropped calls, or missed incoming calls;
  - being unable to place an emergency call (see Section 2);
  - any legal consequence of using, importing, exporting, or operating the software.

  See also [`LICENSE`](LICENSE) Sections 15-16.
- **No hosted service; no data sent to the author:** DialCrypt is software that runs on your own devices. The author does not operate any server, relay, account system, or hosted service. The app has no INTERNET permission, and the software contains no telemetry. The author never receives your keys, messages, contacts, or call data, and therefore cannot recover lost keys or messages, cannot help decrypt anything, and has no way to do so: there is no backdoor and no key escrow.

## 2. User Responsibility for Local Law

Whoever installs or runs DialCrypt is solely responsible for finding out and complying with the laws and carrier terms that apply where they and the other party to a call are located, including:

- **Encryption laws & export controls:** The use, import, and export of encryption technology is regulated differently from country to country. Publishing the source code does not mean you may lawfully use, import, or re-export the software where you are. Check the rules that apply to you before you install or share it.
- **Telecommunications law & carrier terms:** Sending modem signals over a voice channel may violate your carrier's terms of service or trigger anti-fraud controls, which can lead to throttling, call blocking, or termination of your service. Check your contract and local telecommunications regulations.
- **Device modification risks:** Unlocking the bootloader, rooting, and installing a Magisk module that runs a root daemon can void warranties, erase data, damage the device, or cause apps and services that check device integrity to stop working. The daemon changes network and radio settings while a session is active; a fault or power loss at the wrong moment can leave the device in an unexpected state.
- **Emergency communications:** While hardening is active, the daemon cuts network access and restricts the baseband to LTE / NR only. On a network that does not support VoLTE emergency calls, you may be unable to place an emergency call. Do not install DialCrypt on the only phone you rely on to call for help, and never use it for life-safety purposes.
- **Call records are not hidden:** DialCrypt encrypts the content of the text exchanged during a call. It does not hide that the call took place. Your carrier still knows who called whom, when, for how long, and roughly where.

## 3. Responsible-Use Notice

As a compliance reminder and usage notice (and not as an additional condition on the open-source license), do not use DialCrypt for unlawful activities such as:

- Telecom or financial fraud, phishing, or impersonating government agencies, banks, businesses, or other people;
- Harassment, stalking, threats, or other abuse of another person;
- Planning, coordinating, or assisting any crime;
- Evading lawful obligations that apply to you, or interfering with emergency services.

Open-source licensing ([`LICENSE`](LICENSE)) grants copyright and patent permissions only and does not exempt any user from criminal, telecommunications, export-control, or privacy laws.

<!-- SPDX-FileCopyrightText: h4lo-void <https://github.com/h4lo-void/DialCrypt> -->
