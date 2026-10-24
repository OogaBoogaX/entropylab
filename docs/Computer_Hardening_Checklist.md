# Computer hardening checklist

EntropyLab wipes what a web page can reach. Press **End session** in the header
when you are done: it wipes the page, zeroes the WebAssembly memory, empties
the clipboard if EntropyLab copied something there, and asks the browser to
close the tab. Closing the tab and fully quitting the browser end processes
that can retain secret copies and release their memory. This reduces exposure
but does not prove that every copy was erased. Some copies are out of any
page's reach: the operating system writes memory to disk (the pagefile or swap,
the hibernation file, crash dumps), and some browser and system features copy
what you type or see. This checklist reduces those risks. Do it **before** you
load a real key.

A residue audit on 2026-10-03 (Chrome, Edge and Firefox on Windows 11) found
no matching fixture bytes in the browser profile files it inspected, or in the
captured Chrome and Edge processes after the tab closed. Later measured runs
on Windows 11 on 2026-10-06 (Chrome 154.0.8037.98 and Edge 154.0.4258.53) found
2 or 3 mnemonic matches in Edge's main process after *Copy seed phrase* and
tab closure. No matching fixture bytes were found in the captured Chrome
processes, or in the captured Edge processes when the phrase was not copied.
These findings apply to those runs and configurations. They do not establish
erasure of freed memory after quitting, and cannot see what the operating
system had already paged out or saved. This list covers ways to reduce those
additional exposures.

## Every computer

- [ ] **Keep it offline.** Disconnect every network before opening the file.
      Translation, writing aids, cloud clipboards and AI assistants all need
      the network to send anything.
- [ ] **Turn on full-disk encryption.** The pagefile or swap, the hibernation
      file, crash dumps and browser files are then encrypted at rest. Windows:
      Device encryption or BitLocker. macOS: FileVault. Linux: LUKS, chosen
      at install.
- [ ] **Use a private window** (Chrome Incognito, Edge InPrivate, Firefox
      Private Window). It writes no session-restore files, and extensions are
      off in it unless you allowed them.
- [ ] **Press End session when you are done.** It is in the header. It wipes
      the page and asks the browser to close the tab. If the tab stays open,
      close it yourself to let the browser release the tab's resources,
      including a Vanity grind stopped mid-run.
- [ ] **Then quit the browser, not just the tab.** The browser's main process
      can keep copies after the tab closes, out of the page's reach: the Edge
      runs above found mnemonic matches after *Copy seed phrase*. Quitting
      ends that process. Make sure quitting really quits (see *Browsers*
      below). Writing a phrase down instead of copying it avoids sending it
      through the clipboard.
- [ ] **Shut down when you are done; do not sleep.** Sleep keeps memory
      powered, and hibernation writes it to disk.
- [ ] **Do not run EntropyLab in a virtual machine you suspend or
      snapshot.** Both write the machine's whole memory to the host's disk.

## Browsers

- [ ] **Turn off browser translation.** Chrome and Edge send the page's text
      to Google or Microsoft, seed words included when they are on screen.
      Chrome: Settings → Languages → turn off *Use Google Translate*. Edge:
      Settings → Languages → turn off *Offer to translate pages*. Firefox
      translates on the device.
- [ ] **Turn off AI features that read the page.**
    - Chrome: Settings → AI innovations → turn off *History search, powered
      by AI* (it stores the text of pages you visit) and Gemini in Chrome.
    - Edge: Settings → Sidebar → Copilot → turn off *Allow Microsoft to
      access page content*.
- [ ] **Let quitting really quit.** Chrome and Edge keep running after the
      last window closes unless you turn this off.
    - Chrome: Settings → System → *Continue running background apps when
      Google Chrome is closed*.
    - Edge: Settings → System and performance → *Continue running background
      extensions and apps when Microsoft Edge is closed*, and *Startup boost*,
      which can start Edge at sign-in and restart it in the background after
      the last window closes.
- [ ] **Turn off crash reporting.** A crash report can include the page's
      memory.
    - Chrome: Settings → You and Google → Sync and Google services → *Help
      improve Chrome's features and performance*.
    - Firefox: Settings → Privacy & Security → turn off sending crash
      reports.
- [ ] **Tor Browser:** EntropyLab needs WebAssembly, which the *Safer* and
      *Safest* security levels block. It has not been tested on Tor Browser
      yet.

## Windows

- [ ] **Turn hibernation off.** This also turns off Fast Startup, which
      hibernates part of memory. In a terminal opened as administrator:

  ```
  powercfg /h off
  ```

- [ ] **Protect the pagefile.**
    - Pro and Enterprise: encrypt it with a key that changes at every boot.
      Run this as administrator, then restart:

      ```
      fsutil behavior set EncryptPagingFile 1
      ```

    - Home: pagefile encryption is not available, so clear the pagefile at
      shutdown instead. Shutdown gets slower and a power cut skips it, so
      Device encryption matters more here. As administrator:

      ```
      reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
      ```

- [ ] **Turn off clipboard history and sync.** Settings → System → Clipboard.
      Win+V history and cloud sync keep their own copy of everything you copy,
      even after the clipboard itself is emptied.
- [ ] **Turn off Recall.** Settings → Privacy & security → Recall & snapshots
      → turn off *Save snapshots*, then delete the saved snapshots there.
      Recall can capture any window on screen.
- [ ] **Turn off typing insights.** Settings → Time & language → Typing, and
      Settings → Privacy & security → Inking & typing personalization. The
      touch keyboard and text suggestions learn the words you type.
- [ ] **Turn off kernel crash dumps.** System Properties → Advanced → Startup
      and Recovery → Settings → *Write debugging information*: (none).
- [ ] **Keep saved files out of synced folders.** Windows 11 often backs up
      Desktop and Documents to OneDrive. A recovery sheet saved as a PDF
      there is uploaded.

## macOS

- [ ] **FileVault on.** Swap is already encrypted, and FileVault also covers
      the sleep image.
- [ ] **On a laptop, stop the sleep image.** This keeps macOS from writing
      memory to disk when it sleeps:

  ```
  sudo pmset -a hibernatemode 0
  ```

- [ ] **Turn off Handoff.** System Settings → General → AirDrop & Handoff.
      Universal Clipboard copies what you copy to your other Apple devices.
- [ ] **Turn off analytics.** System Settings → Privacy & Security →
      Analytics & Improvements → turn off *Share Mac Analytics*, which sends
      crash reports.
- [ ] **Keep saved files out of iCloud Drive's Desktop and Documents
      sync.**

## Linux

- [ ] **Run without swap, or with zram only.** Turn swap off, then remove or
      comment out the swap lines in `/etc/fstab`. If you need swap, encrypt
      it.

  ```
  sudo swapoff -a
  ```

- [ ] **Turn off hibernation.**

  ```
  sudo systemctl mask hibernate.target hybrid-sleep.target suspend-then-hibernate.target
  ```

- [ ] **Turn off core dumps.** Set `Storage=none` in
      `/etc/systemd/coredump.conf`, and add `ulimit -c 0` to your shell
      profile.
- [ ] **Zero freed memory.** Add `init_on_free=1` to the kernel command line.
      A process's memory is then zeroed the moment it exits, the browser's
      included.
- [ ] **Turn off clipboard history** in your desktop's clipboard manager
      (KDE Klipper, a GNOME clipboard extension).

## The strongest setups

- **Tails** runs from memory, has no swap, and erases memory at shutdown. Its
  Tor Browser needs the *Standard* security level for EntropyLab
  (WebAssembly); it has not been tested there yet.
- **The air-gapped Alpine Linux build** for Raspberry Pi
  ([guide](Airgapped_Alpine_Linux_Build_Guide.md)) runs from RAM, with no
  network drivers and a hardened Chromium.

## Printing

Print recovery sheets on a printer connected directly to the computer. Print
spool files land on disk, and office and network printers often keep a copy of
every job. Saving to PDF writes the sheet to disk too.
