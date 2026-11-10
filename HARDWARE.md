# Hardware support

Run `python3 -m bleforensics.cli hardware` for local capability reporting. Adapter sysfs presence is not proof of usable hardware.

This milestone is offline only. Local Bluetooth adapters, dedicated Nordic sniffers, and SDRs are not integrated. Capture files from supported sources may be imported after authorized collection, but no source device was verified here. For an HCI log, sample rate and RF frequency range are inapplicable. Nordic over-the-air captures require a separate, explicitly supported capture format; they are not silently treated as HCI.
