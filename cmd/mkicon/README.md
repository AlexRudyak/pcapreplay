# cmd/mkicon

Renders the pcapreplay icon (a white waveform on a rounded blue square) into a **multi-resolution Windows `.ico`** using
only the standard library: no image editor and no external tool.

```bash
go run ./cmd/mkicon -o pcapreplay.ico
```

* The shape is defined in a 16 x 16 design space (the same path as the GUI's favicon) and rasterised with 4 x 4
  supersampling for smooth edges at each size.
* Sizes are encoded as PNG images inside the ICO container; `-png FILE` also writes the 256 x 256 frame as a PNG.
* `installer/build.ps1` runs it to produce the installer and executable icon.
