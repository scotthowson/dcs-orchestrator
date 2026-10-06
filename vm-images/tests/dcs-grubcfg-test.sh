#!/bin/bash
# =============================================================================
# dcs-grubcfg against fake /boot directories (no root, no VM): the newest kernel is the default, on every distribution's naming.
# Usage: vm-images/tests/dcs-grubcfg-test.sh   (exit status 0 = all passed)
# =============================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN="$HERE/../common/overlay/usr/local/sbin/dcs-grubcfg"
CONF="$HERE/../common/overlay/etc/default/grub.d"
PASS=0; FAIL=0
check() { if [[ "$3" == "$2" ]]; then PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; else FAIL=$((FAIL + 1)); printf '  FAIL %s (expected %s, got %s)\n' "$1" "$2" "$3"; fi; }
T=$(mktemp -d); trap 'command rm -rf "$T"' EXIT
# mk ROOT kernel-file... : kernels with an initramfs each (initrd.img-X or initramfs-X.img by the name style)
mk() { local r=$1; shift; mkdir -p "$r/boot" "$r/etc/default"; cp -r "$CONF" "$r/etc/default/grub.d"; for k in "$@"; do : > "$r/boot/vmlinuz-$k"; if [[ $k == [0-9]* && $r == *deb* ]]; then : > "$r/boot/initrd.img-$k"; else : > "$r/boot/initramfs-$k.img"; fi; done; }
gen() { DCS_ROOT="$1" bash "$GEN" >/dev/null 2>&1; echo $?; }
first() { grep -m1 'linux /boot/vmlinuz-' "$1/boot/grub/grub.cfg" | sed 's|.*/boot/vmlinuz-\([^ ]*\) .*|\1|'; }
titles() { grep -o "^menuentry '[^']*'" "$1/boot/grub/grub.cfg" | sed "s/menuentry //" | tr '\n' ' ' | sed 's/ $//'; }

echo "dcs-grubcfg: Debian names (the version is in the file name)"
mk "$T/deb" 6.12.41+deb13-cloud-amd64 6.12.48+deb13-cloud-amd64 6.1.0-9-amd64
check "exits 0"                          0 "$(gen "$T/deb")"
check "the newest kernel is the default" 6.12.48+deb13-cloud-amd64 "$(first "$T/deb")"
check "one entry per kernel"             3 "$(grep -c '^menuentry' "$T/deb/boot/grub/grub.cfg")"
check "the older ones are named"         "'DCS' 'DCS (kernel 6.12.41+deb13-cloud-amd64)' 'DCS (kernel 6.1.0-9-amd64)'" "$(titles "$T/deb")"
check "boots by label"                   1 "$(grep -c 'root=LABEL=dcs-root ro' "$T/deb/boot/grub/grub.cfg" | awk '$1 > 0 {print 1}')"
check "the serial console is set up"     1 "$(grep -c 'serial --unit=0 --speed=115200' "$T/deb/boot/grub/grub.cfg" | awk '$1 > 0 {print 1}')"

echo "dcs-grubcfg: Debian's standard kernel next to the cloud one (how a VM gets USB and GPU drivers)"
mk "$T/deb2" 6.12.111+deb13-cloud-amd64 6.12.111+deb13-amd64
gen "$T/deb2" >/dev/null
check "same version: the standard kernel is the default" 6.12.111+deb13-amd64 "$(first "$T/deb2")"
check "the cloud kernel stays as the second entry" "'DCS' 'DCS (kernel 6.12.111+deb13-cloud-amd64)'" "$(titles "$T/deb2")"
mk "$T/deb3" 6.12.111+deb13-amd64 6.12.115+deb13-cloud-amd64
gen "$T/deb3" >/dev/null
check "a newer cloud kernel still wins over an older standard one" 6.12.115+deb13-cloud-amd64 "$(first "$T/deb3")"

echo "dcs-grubcfg: Fedora names, a two-digit version against a one-digit one"
mk "$T/fed" 6.9.12-200.fc44.x86_64 6.19.7-200.fc44.x86_64
gen "$T/fed" >/dev/null
check "6.19 is newer than 6.9"           6.19.7-200.fc44.x86_64 "$(first "$T/fed")"

echo "dcs-grubcfg: Arch names (the package, not the version), the newest first"
mk "$T/arch" linux linux-lts
mkdir -p "$T/arch/usr/lib/modules/7.2.7-arch1-1" "$T/arch/usr/lib/modules/6.18.54-1-lts"
echo linux > "$T/arch/usr/lib/modules/7.2.7-arch1-1/pkgbase"; echo linux-lts > "$T/arch/usr/lib/modules/6.18.54-1-lts/pkgbase"
check "exits 0"                          0 "$(gen "$T/arch")"
check "linux 7.2 is the default over linux-lts 6.18" linux "$(first "$T/arch")"
check "the LTS kernel is the second entry" "'DCS' 'DCS (kernel linux-lts)'" "$(titles "$T/arch")"
mkdir -p "$T/arch2/usr/lib/modules/7.2.7-arch1-1" "$T/arch2/usr/lib/modules/6.18.54-1-lts"
mk "$T/arch2" linux-lts linux
echo linux > "$T/arch2/usr/lib/modules/7.2.7-arch1-1/pkgbase"; echo linux-lts > "$T/arch2/usr/lib/modules/6.18.54-1-lts/pkgbase"
gen "$T/arch2" >/dev/null
check "the order does not depend on the file names' order" linux "$(first "$T/arch2")"
mk "$T/arch3" linux
check "one Arch kernel, the fallback initramfs is not an entry" 1 "$(gen "$T/arch3" >/dev/null; grep -c '^menuentry' "$T/arch3/boot/grub/grub.cfg")"

echo "dcs-grubcfg: no kernel"
mkdir -p "$T/none/boot" "$T/none/etc/default"
check "fails without a kernel"           1 "$(gen "$T/none")"

# Debian and Ubuntu: no update-grub, so the kernel packages' hooks (/etc/kernel/postinst.d and postrm.d, run by run-parts with the
# kernel version and image path) call dcs-grubcfg. Run the image's own hook files the way a kernel package does, after a stand-in for
# initramfs-tools' hook (which makes the initramfs: zz- must come after it, or the new kernel has no initramfs yet and no entry).
echo "kernel hooks (Debian, Ubuntu): installing and removing a kernel rewrites grub.cfg"
HOOKS="$HERE/../apt/overlay/etc/kernel"
for d in postinst.d postrm.d; do
    h="$HOOKS/$d/zz-dcs-grubcfg"
    check "$d/zz-dcs-grubcfg is executable" yes "$([[ -x $h ]] && echo yes || echo no)"
    check "$d/zz-dcs-grubcfg is valid sh" 0 "$(sh -n "$h" 2>/dev/null; echo $?)"
    check "$d/zz-dcs-grubcfg runs the generator the images install" yes "$(grep -qx 'exec /usr/local/sbin/dcs-grubcfg >&2' "$h" && [[ -f $HERE/../common/overlay/usr/local/sbin/dcs-grubcfg ]] && echo yes || echo no)"
done
for df in debian-13 ubuntu-26.04; do
    check "$df's image gets the hooks" yes "$(grep -qx 'COPY apt/overlay/ /' "$HERE/../$df/Dockerfile" && echo yes || echo no)"
done
# a fake root: the generator and the hooks with the generator's path pointed at it (DCS_ROOT), initramfs-tools' stand-in
mk "$T/hk" 6.12.111+deb13-cloud-amd64; gen "$T/hk" >/dev/null
for d in postinst.d postrm.d; do
    mkdir -p "$T/hk/etc/kernel/$d"
    sed "s|/usr/local/sbin/dcs-grubcfg|env DCS_ROOT=$T/hk bash $GEN|" "$HOOKS/$d/zz-dcs-grubcfg" > "$T/hk/etc/kernel/$d/zz-dcs-grubcfg"; chmod 755 "$T/hk/etc/kernel/$d/zz-dcs-grubcfg"
done
printf '#!/bin/sh\n: > "%s/boot/initrd.img-$1"\n' "$T/hk" > "$T/hk/etc/kernel/postinst.d/initramfs-tools"
printf '#!/bin/sh\nrm -f "%s/boot/initrd.img-$1"\n' "$T/hk" > "$T/hk/etc/kernel/postrm.d/initramfs-tools"
chmod 755 "$T/hk/etc/kernel/postinst.d/initramfs-tools" "$T/hk/etc/kernel/postrm.d/initramfs-tools"
check "the hook runs after initramfs-tools' own" "initramfs-tools zz-dcs-grubcfg" "$(run-parts --test "$T/hk/etc/kernel/postinst.d" 2>/dev/null | sed 's|.*/||' | paste -sd' ' || ls "$T/hk/etc/kernel/postinst.d" | LC_ALL=C sort | paste -sd' ')"
kpost() { local v=$1 d=$2; [[ $d == postinst.d ]] && : > "$T/hk/boot/vmlinuz-$v"; [[ $d == postrm.d ]] && rm -f "$T/hk/boot/vmlinuz-$v"
    if command -v run-parts >/dev/null; then run-parts --exit-on-error --arg="$v" --arg="/boot/vmlinuz-$v" "$T/hk/etc/kernel/$d" >/dev/null 2>&1
    else local h; for h in $(ls "$T/hk/etc/kernel/$d" | LC_ALL=C sort); do "$T/hk/etc/kernel/$d/$h" "$v" "/boot/vmlinuz-$v" >/dev/null 2>&1 || return 1; done; fi; echo $?; }
check "postinst of Debian's full kernel exits 0" 0 "$(kpost 6.12.111+deb13-amd64 postinst.d)"
check "the full kernel is the default now" 6.12.111+deb13-amd64 "$(first "$T/hk")"
check "the cloud kernel is the second entry" "'DCS' 'DCS (kernel 6.12.111+deb13-cloud-amd64)'" "$(titles "$T/hk")"
check "postrm of the cloud kernel exits 0" 0 "$(kpost 6.12.111+deb13-cloud-amd64 postrm.d)"
check "only the full kernel is left in the menu" "'DCS'|6.12.111+deb13-amd64" "$(titles "$T/hk")|$(first "$T/hk")"
check "a kernel update (postinst of a newer one) makes it the default" 6.12.115+deb13-amd64 "$(kpost 6.12.115+deb13-amd64 postinst.d >/dev/null; first "$T/hk")"
check "the initramfs list carries ext4 (a module in Debian's full kernel)" yes "$(grep -qx ext4 "$HERE/../common/overlay/etc/initramfs-tools/modules" && echo yes || echo no)"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
