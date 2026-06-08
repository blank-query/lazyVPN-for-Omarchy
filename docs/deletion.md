# File Deletion

A tour of how lazyVPN removes files — what tool gets called, how the result is classified, why CoW filesystems get a different path.

## Two functions, one decision

```
SecureDelete(files, mode) → shred -u <path>   per file
PlainDelete (files, mode) → rm <path>          per file
DeleteForFS(cowFilesystem) returns whichever applies
```

The choice is made once per operation, based on the filesystem type detected at install (stored in `cfg.FSType`).

## Why CoW filesystems use plain `rm`

`shred` overwrites a file's blocks before unlinking. That logic depends on overwrites actually landing on the same physical blocks as the original data — true on ext4 and xfs, **not true on btrfs or ZFS**.

CoW filesystems write to new blocks on every modification. `shred -u` on a btrfs file produces:
- Several writes that go to fresh blocks (CoW behavior)
- The original data sitting in the old blocks
- An unlink that removes the directory entry but doesn't touch the original blocks

The original data is now in unallocated CoW extents — which the next snapshot, defrag, or balance might preserve. Calling shred on btrfs is theater: it generates I/O without actually overwriting anything sensitive.

So lazyVPN's decision: **CoW filesystems get bare `rm`**. No `-f`. No theater. The honest semantics.

Traditional filesystems (ext4, xfs) get `shred -u` because there it actually does what the name suggests.

## Why no `-f` on `rm`

`rm -f` swallows "file doesn't exist" silently. That's normally fine, except lazyVPN uses the absence vs presence of a file to decide what state things are in.

Without `-f`:
- File exists, removed cleanly → exit 0, classified as `Deleted`
- File doesn't exist → exit 1 with "No such file" → classified as `NotPresent`
- File exists but rm failed (permissions, mount busy) → exit 1 with other text → classified as `Failed`

That third category is the one we care about. With `-f` you can't distinguish "didn't need to remove" from "couldn't remove" — both look like success. The interactive uninstaller would then claim a clean removal of files it never touched, which is the bug we're trying to avoid.

## Locale-dependent classification

The `NotPresent` detection greps stderr for `"No such file"`. On a French or German system, `rm`'s error message gets translated and the grep misses, classifying genuine NotPresent as Failed.

The `buildCmd` helper sets `LC_ALL=C` on every spawned command's environment. This forces English error output regardless of the user's locale, so classification works consistently. Don't remove that line.

## Sudo modes

Each delete call carries a `SudoMode`:

- **`NoSudo`** — direct invocation. Used for files in `~/.config/lazyvpn/` and similar user-owned paths.
- **`SudoSilent`** — `sudo -n <cmd>`. Used for sudoers-granted operations like deleting `/etc/sudoers.d/lazyvpn`. If NOPASSWD isn't set, sudo exits non-zero immediately and we surface `ErrAuthRequired`.
- **`SudoInteractive`** — bare `sudo <cmd>`, which prompts for password if cache is cold. Used for journal file deletion in the uninstaller — that operation deliberately has no NOPASSWD entry, so the user gets a prompt and consciously authenticates for log destruction.

The mode is chosen by the caller for each operation, not derived from the filesystem type or the path.

## Failure handling and retry

Every per-file delete produces a `DeleteEvent`:

```
{Path, Mode, Outcome, Err}
```

Where `Outcome` is one of `Deleted`, `NotPresent`, `Failed`. The interactive uninstaller groups failed events and offers a per-file retry / skip prompt. CoW users whose primary `rm` fails can also opt into the `shred` fallback (which probably won't help on CoW, but it's there for completeness and consistency with the cross-FS API).

## What the uninstaller does NOT do

- Doesn't shell-glob your config dir. Every file path is constructed explicitly.
- Doesn't `rm -rf`. Directories are removed with `os.Remove` (rmdir), which only succeeds when empty. If something unexpected is left behind, you'll see it.
- Doesn't follow symlinks blindly. Path-traversal checks via `filepath.EvalSymlinks` before opening anything in user-controlled directories.
- Doesn't shred files on CoW filesystems and pretend it worked.
