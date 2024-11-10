VMA extractor
=============

`vma.py` implements an extraction tool for the VMA backup format used by
[Proxmox](https://www.proxmox.com). The tool is implemented in Python3.

## Usage:
```sh
./vma.py path/to/source.vma path/to/target/directory
```

I think it is pretty important to be able to read Proxmox backups outside of a
Proxmox environment. Yet, porting their VMA implementation to a standalone
tool proved difficult. VMA-Reader and VMA-Writer are implemented as patches to
the Proxmox-patched version and Qemu and are thus very difficult to compile on
non-Proxmox systems.

The format specification can be found on [git.proxmox.com](https://git.proxmox.com/?p=pve-qemu.git;a=blob_plain;f=vma_spec.txt;hb=refs/heads/master).

## Sparse Files
You can use the --sparse option to write sparse files. Sparse files are files that attempt to use file system space more efficiently when blocks are empty. This can save disk space and speed up the extraction process.

Example:
```
./vma.py --sparse path/to/source.vma path/to/target/directory
```
