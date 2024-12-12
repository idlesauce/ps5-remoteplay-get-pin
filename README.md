# ps5-remoteplay-get-pin

Apparently most of the checks are just in ShellUI, the `sceRemoteplayGeneratePinCode` function works for offline activated accounts without any patching, so after you pair you can even use it unjailbroken.

## Usage
1. Offline activate your account using [offact](https://github.com/ps5-payload-dev/offact).
    - Download: https://github.com/ps5-payload-dev/websrv/releases/
    - You can follow this tutorial from Modded Warfare on how to set this up: https://youtu.be/CFTIWX0JJRI?t=202
        - The video description has a link to the offact repo, however you should download offact from the websrv releases page as those are newer builds.
    - The auto-generated id is fine to use, you dont need a real psn id.
    - On very low firmwares the websrv frontend may be broken in the ps5's browser, for the time being you can open offact by going to `http://<yourps5ip>:8080/` on your pc.
1. Reboot the console if you have not done so since you offline activated your account.
1. Inject this payload using john-tornblom's elf loader on port 9021.
    - The pairing pin and base64 encoded id will be displayed in a notification as well as printed to stdout.
        - To see stdout you can inject like this: `socat -t 99999999 - TCP:<yourps5ip>:9021 < rp-get-pin.elf`
    - Only the displayed account id will be accepted when pairing, which is the currently logged in user.
    - If you want to cancel the pairing you can send the payload again.
1. Connect with [chiaki](https://sr.ht/~thestr4ng3r/chiaki/) or [chiaki-ng](https://streetpea.github.io/chiaki-ng/)
    - The official Remote Play app may also work (havent tried it myself yet). For this you'll need to set your proper account id associated with your psn account in offact.
