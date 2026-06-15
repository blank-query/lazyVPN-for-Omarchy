# Theming

LazyVPN automatically matches your [Omarchy](https://omarchy.org) theme. There's no
configuration and no separate theme file to maintain — whatever theme your desktop is
using, the LazyVPN TUI uses the same palette.

## How it works

On startup, LazyVPN reads the active Omarchy theme's color palette from:

```
~/.config/omarchy/current/theme/colors.toml
```

Those values are mapped onto the interface — `accent` drives the focused-pane border and
brand text, `background` / `foreground` set the base colors, and the standard `color0`–
`color15` slots feed the success / warning / danger / muted / highlight styling. If you're
not on Omarchy (or the theme file isn't present), LazyVPN falls back to a built-in dark
palette, so it always renders cleanly.

## Switching themes

Change your Omarchy theme the usual way:

- **Omarchy menu:** `Super + Alt + Space` → Style → Theme (or jump straight to the theme switcher with `Super + Ctrl + Shift + Space`)
- **Command line:** `omarchy-theme-set nord`

The theme is read **once at startup**, so **relaunch LazyVPN** after switching to pick up the
new colors.

For everything Omarchy's theming system can do — switching, installing community themes, and
building your own — see the official **[Omarchy Manual: Themes](https://learn.omacom.io/2/the-omarchy-manual/52/themes)**.

## Gallery

Every theme Omarchy ships with by default, shown on the LazyVPN dashboard:

<table>
  <tr>
    <td align="center"><strong>Catppuccin</strong><br><img src="images/themes/catppuccin.png" width="420"></td>
    <td align="center"><strong>Catppuccin Latte</strong><br><img src="images/themes/catppuccin-latte.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Ethereal</strong><br><img src="images/themes/ethereal.png" width="420"></td>
    <td align="center"><strong>Everforest</strong><br><img src="images/themes/everforest.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Flexoki Light</strong><br><img src="images/themes/flexoki-light.png" width="420"></td>
    <td align="center"><strong>Gruvbox</strong><br><img src="images/themes/gruvbox.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Hackerman</strong><br><img src="images/themes/hackerman.png" width="420"></td>
    <td align="center"><strong>Kanagawa</strong><br><img src="images/themes/kanagawa.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Lumon</strong><br><img src="images/themes/lumon.png" width="420"></td>
    <td align="center"><strong>Matte Black</strong><br><img src="images/themes/matte-black.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Miasma</strong><br><img src="images/themes/miasma.png" width="420"></td>
    <td align="center"><strong>Nord</strong><br><img src="images/themes/nord.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Osaka Jade</strong><br><img src="images/themes/osaka-jade.png" width="420"></td>
    <td align="center"><strong>Retro 82</strong><br><img src="images/themes/retro-82.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Ristretto</strong><br><img src="images/themes/ristretto.png" width="420"></td>
    <td align="center"><strong>Rosé Pine</strong><br><img src="images/themes/rose-pine.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Tokyo Night</strong><br><img src="images/themes/tokyo-night.png" width="420"></td>
    <td align="center"><strong>Vantablack</strong><br><img src="images/themes/vantablack.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>White</strong><br><img src="images/themes/white.png" width="420"></td>
    <td></td>
  </tr>
</table>
