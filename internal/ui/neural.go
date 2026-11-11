package ui

import (
	"fmt"
	"strings"
)

// neuralNetwork is original terminal artwork, not a fetched image or terminal font.
// Rendering is deterministic and heap use is bounded by the small fixed canvas.
var brainOutline = []string{
	"         ╭────────╮    ╭────────╮",
	"     ╭───╯        ╰────╯        ╰───╮",
	"   ╭─╯                              ╰─╮",
	"  ╭╯                                  ╰╮",
	"  │                                    │",
	"  │                                    │",
	"  ╰╮                                  ╭╯",
	"   ╰╮                                ╭╯",
	"    ╰╮                              ╭╯",
	"     ╰╮                            ╭╯",
	"      ╰─────╮              ╭─────╯",
	"            ╰──────┬───────╯",
}

type neuralNode struct{ x, y int }

var neuralNodes = [...]neuralNode{
	{10, 3}, {17, 2}, {25, 2}, {32, 3},
	{6, 5}, {14, 5}, {21, 5}, {29, 5}, {36, 5},
	{9, 8}, {17, 8}, {25, 8}, {33, 8},
	{14, 10}, {25, 10},
}

var neuralEdges = [...][2]int{
	{0, 1}, {1, 2}, {2, 3}, {0, 4}, {0, 5}, {1, 5},
	{1, 6}, {2, 6}, {2, 7}, {3, 7}, {3, 8}, {4, 5},
	{5, 6}, {6, 7}, {7, 8}, {4, 9}, {5, 9}, {5, 10},
	{6, 10}, {6, 11}, {7, 11}, {7, 12}, {8, 12},
	{9, 13}, {10, 13}, {10, 14}, {11, 14}, {12, 14}, {13, 14},
}

// NeuralFrame produces a text-only brain when color is false and colored neural
// impulses when true. Motion can be disabled by calling it with a constant tick.
func NeuralFrame(tick uint64, color bool) []string {
	const w = 42
	h := len(brainOutline)
	canvas := make([][]rune, h)
	for y, line := range brainOutline {
		canvas[y] = make([]rune, w)
		for x := range canvas[y] {
			canvas[y][x] = ' '
		}
		for x, r := range []rune(line) {
			if x < w {
				canvas[y][x] = r
			}
		}
	}
	// Symbols 1 = circuitry, 2 = node, 3 = moving signal. The renderer places
	// one color transition per contiguous run, not one expensive ANSI sequence
	// per character.
	bright := make([][]uint8, h)
	for y := range bright {
		bright[y] = make([]uint8, w)
	}
	for i, e := range neuralEdges {
		a, b := neuralNodes[e[0]], neuralNodes[e[1]]
		dx, dy := b.x-a.x, b.y-a.y
		steps := absInt(dx)
		if absInt(dy) > steps {
			steps = absInt(dy)
		}
		if steps == 0 {
			continue
		}
		pulse := int((tick/2 + uint64(i*3)) % uint64(steps+6))
		for j := 0; j <= steps; j++ {
			x := a.x + dx*j/steps
			y := a.y + dy*j/steps
			if x < 0 || y < 0 || x >= w || y >= h {
				continue
			}
			if canvas[y][x] == ' ' {
				switch {
				case dy == 0:
					canvas[y][x] = '─'
				case dx == 0:
					canvas[y][x] = '│'
				case dx*dy > 0:
					canvas[y][x] = '╲'
				default:
					canvas[y][x] = '╱'
				}
				bright[y][x] = 1
			}
			if j == pulse && j > 0 && j < steps && bright[y][x] > 0 {
				canvas[y][x], bright[y][x] = '◆', 3
			}
		}
	}
	for i, n := range neuralNodes {
		if n.x >= w || n.y >= h {
			continue
		}
		if (tick+uint64(i*7))%23 < 4 {
			canvas[n.y][n.x], bright[n.y][n.x] = '◉', 3
		} else {
			canvas[n.y][n.x], bright[n.y][n.x] = '●', 2
		}
	}
	lines := make([]string, h)
	for y := range canvas {
		if !color {
			lines[y] = strings.TrimRight(string(canvas[y]), " ")
			continue
		}
		var s strings.Builder
		last := uint8(255)
		end := len(canvas[y])
		for end > 0 && canvas[y][end-1] == ' ' {
			end--
		}
		for x, ch := range canvas[y][:end] {
			level := bright[y][x]
			if level != last {
				switch level {
				case 3:
					s.WriteString("\x1b[38;5;159m")
				case 2:
					s.WriteString("\x1b[38;5;81m")
				case 1:
					s.WriteString("\x1b[38;5;67m")
				default:
					s.WriteString("\x1b[38;5;61m")
				}
				last = level
			}
			s.WriteRune(ch)
		}
		s.WriteString("\x1b[0m")
		lines[y] = s.String()
	}
	return lines
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func neuralCaption(tick uint64, busy bool) string {
	if busy {
		return fmt.Sprintf("  ◉ ENGINE ACTIVE   %s", []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}[tick%10])
	}
	dots := strings.Repeat("·", int(tick%4))
	return "  ◉ NEURAL LINK READY" + dots
}
