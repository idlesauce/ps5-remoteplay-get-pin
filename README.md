# ps5-remoteplay-get-pin
Generate Remote Play pairing PIN for offline activated accounts.

Apparently most of the checks preventing Remote Play from working on offline activated accounts are just in ShellUI, the `sceRemoteplayGeneratePinCode` function works without any patching, so after you pair you can even use it unjailbroken. 

## Usage
Full guide on setting this up from Modded Warfare: https://www.youtube.com/watch?v=8ijpU4-Qwz4

1. Offline activate your account using [offact](https://github.com/ps5-payload-dev/offact).
    - Download: https://github.com/ps5-payload-dev/websrv/releases/
    - The auto-generated id is fine to use, you dont need a real psn id if you're fine with using chiaki.
    - To be able to use the official Remote Play app you'll need to set your proper account id associated with your psn account in offact.
    - On very low firmwares the websrv frontend may be broken in the ps5's browser, for the time being you can open offact by going to `http://<yourps5ip>:8080/` on your pc.
1. Reboot the console if you have not done so since you offline activated your account.
    - From a quick test I did this step wasn't necessary, however others reported this as being a required step. You try sending the payload right away, pairing and reboot only if the pairing/connecting fails.
1. Inject this payload using john-tornblom's elf loader on port 9021.
    - The pairing pin and base64 encoded id will be displayed in a notification as well as printed to stdout.
        - To see stdout you can inject like this: `socat -t 99999999 - TCP:<yourps5ip>:9021 < rp-get-pin.elf`
    - Only the displayed account id will be accepted when pairing, which is the currently logged in user.
    - If you want to cancel the pairing you can send the payload again.
1. Connect with [chiaki](https://sr.ht/~thestr4ng3r/chiaki/), [chiaki-ng](https://streetpea.github.io/chiaki-ng/) or the official Remote Play app.

## Thanks
- Nicit - testing
- [astrelsky](https://github.com/astrelsky/) - ptrace examples
- [john-tornblom](https://github.com/john-tornblom/) - sdk and ptrace examples
