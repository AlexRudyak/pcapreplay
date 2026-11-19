// Command mkicon renders the pktreplay icon (a white waveform on a rounded blue
// square) into a multi-resolution Windows .ico file using only the standard
// library. Usage: mkicon -o pktreplay.ico
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

// The waveform lives in a 16x16 design space (same path as the GUI favicon).
var wave = [][2]float64{{2, 8}, {5, 8}, {7, 3}, {10, 13}, {12, 8}, {14, 8}}

const (
	strokeW = 1.8
	cornerR = 3.6
)

func distSeg(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

func inRounded(x, y float64) bool {
	if x < 0 || y < 0 || x > 16 || y > 16 {
		return false
	}
	cx := math.Max(cornerR, math.Min(16-cornerR, x))
	cy := math.Max(cornerR, math.Min(16-cornerR, y))
	return math.Hypot(x-cx, y-cy) <= cornerR
}

func inStroke(x, y float64) bool {
	for i := 0; i+1 < len(wave); i++ {
		if distSeg(x, y, wave[i][0], wave[i][1], wave[i+1][0], wave[i+1][1]) <= strokeW/2 {
			return true
		}
	}
	return false
}

// render draws the icon at size x size with 4x4 supersampling for smooth edges.
func render(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	bg := [3]float64{0x2f, 0x6f, 0xed}
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var a, r, g, b float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) * 16 / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) * 16 / float64(size)
					if !inRounded(x, y) {
						continue
					}
					a++
					if inStroke(x, y) {
						r, g, b = r+255, g+255, b+255
					} else {
						r, g, b = r+bg[0], g+bg[1], b+bg[2]
					}
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{uint8(r/a + 0.5), uint8(g/a + 0.5), uint8(b/a + 0.5), uint8(255*a/(ss*ss) + 0.5)})
		}
	}
	return img
}

// main renders the icon at each standard size and writes them into one .ico file.
func main() {
	out := flag.String("o", "pktreplay.ico", "output .ico file")
	pngOut := flag.String("png", "", "also write the 256x256 frame as a PNG (for previews and docs)")
	flag.Parse()
	if *pngOut != "" {
		var buf bytes.Buffer
		png.Encode(&buf, render(256))
		if err := os.WriteFile(*pngOut, buf.Bytes(), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	sizes := []int{16, 24, 32, 48, 64, 128, 256}
	var frames [][]byte
	for _, s := range sizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, render(s)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		frames = append(frames, buf.Bytes())
	}
	var ico bytes.Buffer
	le := binary.LittleEndian
	binary.Write(&ico, le, [3]uint16{0, 1, uint16(len(sizes))}) // reserved, type=icon, count
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		dim := byte(s)
		if s >= 256 {
			dim = 0 // 0 means 256
		}
		ico.Write([]byte{dim, dim, 0, 0})
		binary.Write(&ico, le, uint16(1))  // planes
		binary.Write(&ico, le, uint16(32)) // bits per pixel
		binary.Write(&ico, le, uint32(len(frames[i])))
		binary.Write(&ico, le, uint32(offset))
		offset += len(frames[i])
	}
	for _, f := range frames {
		ico.Write(f)
	}
	if err := os.WriteFile(*out, ico.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
