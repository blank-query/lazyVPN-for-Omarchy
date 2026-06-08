package ui

// Spinner is a lightweight braille spinner driven by existing tick messages.
type Spinner struct {
	frame int
}

var spinnerFrames = [10]rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// Tick advances the spinner by one frame.
func (s *Spinner) Tick() { s.frame = (s.frame + 1) % len(spinnerFrames) }

// View returns the current spinner character as a string.
func (s *Spinner) View() string { return string(spinnerFrames[s.frame]) }
