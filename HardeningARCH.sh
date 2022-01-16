#!/bin/bash -e

#    Arch Hardening Script
#    Copyright (C) 2019  madaidan
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# https://gitlab.com/madaidan/arch-hardening-script
# dead on madaidan's page in Gitlab so brought it over for analysis, can be converted to Debian also.
# BELOW is a backup of the mac spoofer script
#        ##!/bin/bash
#        
#        # Get list of network interfaces. Excludes loopback and virtual machine interfaces.
#        interfaces=$(ls /sys/class/net | grep -v 'lo' | grep -v 'tun0' | grep -v "virbr")
#        
#        # Spoof the MAC address of each.
#        for i in ${interfaces}
#        do
#          macchanger -e $i >/dev/null # Hide the output so it can't be discovered with systemd logs.
#        done

# might need to run sudo apt-get install -y macchanger or check it's installed here aswell...

# is fail2ban in here? quick note , gotta run

# anyway back to the show


while test $# -gt 0; do
        case "$1" in
                --disable-checks)
                                # Disable script_checks.
                                disable_checks=1
                                exit 1
                                ;;
                *)
                                echo "'${*}' is not a correct flag."
                                exit 1
                                ;;

        esac
done

create_grub_directory() {
  # Create /etc/default/grub.d if it doesn't already exist.
  if ! [ -d /etc/default/grub.d ]; then
    mkdir -m 755 /etc/default/grub.d

    # Make /etc/default/grub source grub.d.
    # shellcheck disable=SC2016
    echo '
for i in /etc/default/grub.d/*.cfg ; do
if [ -e "${i}" ]; then
  . "${i}"
fi
done
' >> /etc/default/grub
  fi
}

syslinux_append() {
  new_boot_parameters="$1"

  # Get list of current boot parameters.
  syslinux_parameters=$(grep -v "Fallback" /boot/syslinux/syslinux.cfg | grep -C 2 "MENU LABEL Arch Linux" | grep "APPEND")

  # Add new boot parameters.
  sed -i "s|${syslinux_parameters}|${syslinux_parameters} ${new_boot_parameters}|" /boot/syslinux/syslinux.cfg
}

script_checks() {
  if ! [ "${disable_checks}" = "1" ]; then
    # Check for root
    if [[ "$(id -u)" -ne 0 ]]; then
      echo "This script needs to be run as root."
      exit 1
    fi

    # Check if on Arch Linux or a derivative.
    if grep "Arch Linux" /etc/os-release &>/dev/null; then
      true
    elif grep "Manjaro Linux" /etc/os-release &>/dev/null; then
      true
    else
      echo "This script can only be used on Arch Linux or Manjaro."
      exit 1
    fi

    # Check which bootloader is being used.
    if [ -d /boot/grub ]; then
      use_grub="y"
      # Create /etc/default/grub.d if it doesn't already exist.
      create_grub_directory
    elif [ -d /boot/syslinux ]; then
      use_syslinux="y"

      if ! grep "MENU LABEL Arch Linux" /boot/syslinux/syslinux.cfg >/dev/null; then
        echo "The 'Arch Linux' menu label is missing from your Syslinux configuration file."
        exit 1
      fi
    else
      echo "This script can only be used with GRUB or syslinux."
      exit 1
    fi

    # Check if using systemd.
    # shellcheck disable=SC2009
    if ! ps -p 1 | grep systemd &>/dev/null; then
      echo "This script can only be used with systemd."
      exit 1
    fi
  fi
}

sysctl_hardening() {
  ## Sysctl
  read -r -p "Harden the kernel with sysctl? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#sysctl) (y/n) " sysctl
  if [ "${sysctl}" = "y" ]; then
    # Hide kernel symbols in /proc/kallsyms.
    read -r -p "Hide kernel symbols in /proc/kallsyms? (y/n) " kallsyms
    if [ "${kallsyms}" = "y" ]; then
      echo "kernel.kptr_restrict=2" > /etc/sysctl.d/kptr_restrict.conf
    fi

    # Restrict dmesg to root.
    read -r -p "Restrict dmesg to root only? (y/n) " dmesg
    if [ "${dmesg}" = "y" ]; then
      echo "kernel.dmesg_restrict=1" > /etc/sysctl.d/dmesg_restrict.conf
    fi

    # Harden BPF JIT compiler.
    read -r -p "Harden the BPF JIT compiler? (y/n) " jit
    if [ "${jit}" = "y" ]; then
      echo "kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2" > /etc/sysctl.d/harden_bpf.conf
    fi

    # Restrict ptrace to root.
    read -r -p "Restrict ptrace to root only? (y/n) " ptrace
    if [ "${ptrace}" = "y" ]; then
      echo "kernel.yama.ptrace_scope=2" > /etc/sysctl.d/ptrace_scope.conf
    fi

    # Disable kexec.
    read -r -p "Disable kexec? (y/n) " kexec
    if [ "${kexec}" = "y" ]; then
      echo "kernel.kexec_load_disabled=1" > /etc/sysctl.d/kexec.conf
    fi

    # Harden the TCP/IP stack.
    read -r -p "Harden the TCP/IP stack? (y/n) " tcp_ip_stack_hardening
    if [ "${tcp_ip_stack_hardening}" = "y" ]; then
      # Enable TCP syncookies.
      read -r -p "Enable TCP syncookies? (y/n) " tcp_syncookies
      if [ "${tcp_syncookies}" = "y" ]; then
        echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Protect against time-wait assassination.
      read -r -p "Protect against time-wait assassination? (y/n) " tcp_timewait_assassination
      if [ "${tcp_timewait_assassination}" = "y" ]; then
        echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Enable reverse path filtering.
      read -r -p "Enable reverse path filtering (rp_filter)? (y/n) " enable_rp_filter
      if [ "${enable_rp_filter}" = "y" ]; then
         echo "net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Disable ICMP redirect acceptance.
      read -r -p "Disable ICMP redirect acceptance? (y/n) " disable_icmp_redirect_acceptance
      if [ "${disable_icmp_redirect_acceptance}" = "y" ]; then
        echo "net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Disable ICMP redirect sending.
      read -r -p "Disable ICMP redirect sending? (y/n) " disable_icmp_redirect_sending
      if [ "${disable_icmp_redirect_sending}" = "y" ]; then
        echo "net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Ignore ICMP requests.
      read -r -p "Ignore ICMP requests? (y/n) " ignore_icmp
      if [ "${ignore_icmp}" = "y" ]; then
        echo "net.ipv4.icmp_echo_ignore_all=1" >> /etc/sysctl.d/tcp_hardening.conf
      fi
    fi

    # Improve ASLR for mmap.
    read -r -p "Improve ASLR effectiveness for mmap? (y/n) " improve_aslr
    if [ "${improve_aslr}" = "y" ]; then
      echo "vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16" > /etc/sysctl.d/mmap_aslr.conf
    fi

    # Disable TCP timestamps
    read -r -p "Disable TCP timestamps? (y/n) " timestamps
    if [ "${timestamps}" = "y" ]; then
      echo "net.ipv4.tcp_timestamps=0" > /etc/sysctl.d/tcp_timestamps.conf
    fi

    # Disable the SysRq key.
    read -r -p "Disable the SysRq key? (y/n) " disable_sysrq
    if [ "${disable_sysrq}" = "y" ]; then
      echo "kernel.sysrq=0" > /etc/sysctl.d/sysrq.conf
    fi

    # Disable unprivileged user namespaces.
    read -r -p "Disable unprivileged user namespaces? (y/n) " disable_unprivileged_userns
    if [ "${disable_unprivileged_userns}" = "y" ]; then
      echo "kernel.unprivileged_userns_clone=0" > /etc/sysctl.d/unprivileged_users_clone.conf
    fi

    # Disable TCP SACK.
    read -r -p "Disable TCP SACK? (y/n) " disable_sack
    if [ "${disable_sack}" = "y" ]; then
      echo "net.ipv4.tcp_sack=0" > /etc/sysctl.d/tcp_sack.conf
    fi
  fi
}

boot_parameter_hardening() {
  ## Boot Parameters.
  read -r -p "Harden the kernel through boot parameters? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#boot_parameters) (y/n) " bootparams
  if [ "${bootparams}" = "y" ]; then
    # GRUB-specific configuration.
    if [ "${use_grub}" = "y" ]; then
      # Add kernel hardening boot parameters.
      # shellcheck disable=SC2016
      echo '''GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX slab_nomerge slub_debug=FZP mce=0 page_poison=1 pti=on mds=full,nosmt"''' > /etc/default/grub.d/40_kernel_hardening.cfg
    elif [ "${use_syslinux}" = "y" ]; then
      # Append new boot parameters.
      syslinux_append "slab_nomerge slub_debug=FZP mce=0 page_poison=1 pti=on mds=full,nosmt module.sig_enforce=1"
    fi

    # Require kernel modules to be signed with a valid key.
    # This prevents out-of-tree modules from being loaded so it's separate from the bulk of the hardening parameters.
#    read -r -p "Require kernel modules to be signed with a valid key? (y/n) " require_signed_modules
#    if [ "${require_signed_modules}" = "y" ]; then
#      # GRUB-specific configuration.
#      if [ "${use_grub}" = "y" ]; then
        # Add kernel hardening boot parameters.
        # shellcheck disable=SC2016
#        echo '''GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX module.sig_enforce=1"''' > /etc/default/grub.d/40_require_signed_modules.cfg
#      elif [ "${use_syslinux}" = "y" ]; then
        # Append new boot parameters.
#        syslinux_append "module.sig_enforce=1"
#      fi
#    fi

# PANZER: Requires secure boot, later revisions may want this but ported to other distros might lock system out depending on BIOS / OS

    # Disable IPv6.
    read -r -p "Do you want to disable IPv6? (y/n) [ not recommended ] " disable_ipv6
    if [ "${disable_ipv6}" = "y" ]; then
      if [ "${use_grub}" = "y" ]; then
        # shellcheck disable=SC2016
        echo '''GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX ipv6.disable=1"''' > /etc/default/grub.d/40_disable_ipv6.cfg
      elif [ "${use_syslinux}" = "y" ]; then
        syslinux_append "ipv6.disable=1"
      fi
    fi

    if [ "${use_grub}" = "y" ]; then
      # Regenerate GRUB configuration file.
      grub-mkconfig -o /boot/grub/grub.cfg
    fi
  fi
}

# hidepid() {
  ## Hidepid.
#  read -r -p "Use hidepid to hide other users' processes? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#hidepid) (y/n) " hidepid
#  if [ "${hidepid}" = "y" ]; then
    # Enable hidepid.
#    echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /etc/fstab

    # Create proc group if it doesn't exist already.
#    if ! grep "proc" /etc/group &>/dev/null; then
#      groupadd proc
#    fi

    # Create drop-in directory for systemd-logind if it doesn't already exist.
#    if ! [ -d "/etc/systemd/system/systemd-logind.service.d/" ]; then
#      mkdir /etc/systemd/system/systemd-logind.service.d/
#    fi

    # Create exception for systemd-logind so user sessions still work.
#    echo "[Service]
#SupplementaryGroups=proc" > /etc/systemd/system/systemd-logind.service.d/hidepid.conf
#  fi

# PANZER: not sure this is really needed / effective

#}

disable_nf_conntrack_helper() {
  ## Disable Netfilter connection tracking helper.
  read -r -p "Disable the Netfilter automatic conntrack helper assignment? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#nf_conntrack_helper) (y/n) " disable_conntrack_helper
  if [ "${disable_conntrack_helper}" = "y" ]; then
    echo "options nf_conntrack nf_conntrack_helper=0" > /etc/modprobe.d/no-conntrack-helper.conf
  fi
}

#install_linux_hardened() {
  ## Linux-Hardened
#  read -r -p "Install linux-hardened? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#linux-hardened) (y/n) " linux_hardened
#  if [ "${linux_hardened}" = "y" ]; then
    # Install linux-hardened.
#    pacman -S --noconfirm -q linux-hardened linux-hardened-headers

    # Re-generate GRUB configuration.
#    grub-mkconfig -o /boot/grub/grub.cfg
#  fi
#
# PANZER: I don't think this works with Manjaro and it 100% won't work on Debian based OS
}

apparmor() {
  ## Apparmor
  read -r -p "Enable apparmor? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#MAC) (y/n) " enable_apparmor
  if [ "${enable_apparmor}" = "y" ]; then
    # Check if apparmor is installed and if not, install it
    if ! pacman -Qq apparmor &>/dev/null; then
      pacman -S --noconfirm -q apparmor
    fi

    # Enable AppArmor systemd service.
    systemctl enable apparmor.service

    # Enable AppArmor with a boot parameter.
    if [ "${use_grub}" = "y" ]; then
      # shellcheck disable=SC2016
      echo '''GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX apparmor=1 security=apparmor audit=1"''' > /etc/default/grub.d/40_enable_apparmor.cfg

      # Re-generate GRUB configuration.
      grub-mkconfig -o /boot/grub/grub.cfg
    elif [ "${use_syslinux}" = "y" ]; then
      syslinux_append "apparmor=1 security=apparmor audit=1"
    fi
  fi
}

get_firejail() {
  ## Firejail
  read -r -p "Install firejail? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#sandboxes) (y/n) " install_firejail
  if [ "${install_firejail}" = "y" ]; then
    # Installs firejail if it isn't already.
    if ! pacman -Qq firejail &>/dev/null; then
      pacman -S --noconfirm -q firejail
    fi
  fi
}

restrict_root() {
  ## Restricting root
  # Clear /etc/securetty
  read -r -p "Clear /etc/securetty? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#securetty) (y/n) " securetty
  if [ "${securetty}" = "y" ]; then
    echo "" > /etc/securetty
  fi

  # Restricting su to users in the wheel group.
  read -r -p "Restrict su to users in the wheel group? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#restricting_su) (y/n) " restrict_su
  if [ "${restrict_su}" = "y" ]; then
    # Restricts su by editing files in /etc/pam.d/
    sed -i 's/#auth		required	pam_wheel.so use_uid/auth		required	pam_wheel.so use_uid/' /etc/pam.d/su
    sed -i 's/#auth		required	pam_wheel.so use_uid/auth		required	pam_wheel.so use_uid/' /etc/pam.d/su-l
  fi

  # Lock the root account.
  read -r -p "Lock the root account? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#locking_root) (y/n) " lock_root_account
  if [ "${lock_root_account}" = "y" ]; then
    passwd -l root
  fi

  # Checks if SSH is installed before asking.
  if [ -x "$(command -v ssh)" ]; then
    # Deny root login via SSH.
    read -r -p "Deny root login via SSH? [recommended] (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#denying_root_login_ssh) (y/n) " deny_root_ssh
    if [ "${deny_root_ssh}" = "y" ]; then
      echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
    fi
  fi
}

firewall() {
  ## Firewall
  read -r -p "Install and configure UFW? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#firewalls) (y/n) " install_ufw
  if [ "${install_ufw}" = "y" ]; then
    # Installs ufw if it isn't already.
    if ! pacman -Qq ufw &>/dev/null; then
      pacman -S --noconfirm -q ufw
    fi

    # Enable UFW.
    ufw enable
    systemctl enable ufw.service

    # Deny all incoming traffic.
    ufw default deny incoming # Also disables ICMP timestamps
  fi
}

setup_tor() {
  ## Tor.
  read -r -p "Do you want to install Tor? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#tor) (y/n) " install_tor
  if [ "${install_tor}" = "y" ]; then
    # Installs Tor if it isn't already.
    if ! pacman -Qq tor &>/dev/null; then
      pacman -S --noconfirm -q tor
    fi

    # Force Pacman through Tor
    read -r -p "Force pacman through Tor? (See: https://theprivacyguide1.github.io/linux_hardening_guide.html#stream_isolation) (y/n) " pacman_tor
    if [ "${pacman_tor}" = "y" ]; then
      # Configure a SocksPort for Pacman.
      echo '''
# Pacman SocksPort
SocksPort 9062''' >> /etc/tor/torrc
      sed -i 's/#XferCommand = \/usr\/bin\/curl -L -C - -f -o %o %u/XferCommand = \/usr\/bin\/curl --socks5-hostname localhost:9062 --continue-at - --fail --output %o %u/' /etc/pacman.conf

      # Only use https mirrors incase of compromised exit nodes.
      sed -i 's/Server = http:/#Server = http:/' /etc/pacman.d/mirrorlist
    fi

    # Enables tor systemd service.
    systemctl enable --now tor.service
  fi
}

configure_hostname() {
  ## Change hostname to a generic one.
  read -r -p "Change hostname to 'host'? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#hostnames) (y/n) " hostname
  if [ "${hostname}" = "y" ]; then
    hostnamectl set-hostname host
  fi
}

block_wireless_devices() {
  ## Wireless devices
  read -r -p "Block all wireless devices with rfkill? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#bluetooth) (y/n) " block_wireless
  if [ "${block_wireless}" = "y" ]; then
    # Uses rfkill to block all wireless devices.
    rfkill block all

    # Unblock WiFi.
    read -r -p "Unblock WiFi? (y/n) " unblock_wifi
    if [ "${unblock_wifi}" = "y" ]; then
      rfkill unblock wifi
    fi

    # Blacklist bluetooth kernel module.
    read -r -p "Blacklist the bluetooth kernel module? (y/n) " blacklist_bluetooth
    if [ "${blacklist_bluetooth}" = "y" ]; then
      echo "install btusb /bin/true
install bluetooth /bin/true" > /etc/modprobe.d/blacklist-bluetooth.conf
    fi
  fi
}

mac_address_spoofing() {
  ## MAC Address Spoofing.
  read -r -p "Spoof MAC address automatically at boot? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#mac_address) (y/n) " spoof_mac_address
  if [ "${spoof_mac_address}" = "y" ]; then
    read -r -p "Use macchanger or NetworkManager? " which_mac_spoofer
    if [ "${which_mac_spoofer}" = "macchanger" ]; then
      # Installs macchanger if it isn't already.
      if ! pacman -Qq macchanger &>/dev/null; then
        pacman -S --noconfirm -q macchanger
      fi

      # Get mac spoofing script.
      mkdir -m 755 /usr/lib/arch-hardening-script
      curl -s --tlsv1.2 --proto =https https://gitlab.com/madaidan/arch-hardening-script/raw/master/spoof-mac-addresses.sh > /usr/lib/arch-hardening-script/spoof-mac-addresses

      # Set permissions.
      chown root -R /usr/lib/arch-hardening-script
      chmod 744 /usr/lib/arch-hardening-script/spoof-mac-addresses

      # Creates systemd service for MAC spoofing.
      cat <<EOF > /etc/systemd/system/macspoof.service
[Unit]
Description=Spoofs MAC addresses
Wants=network-pre.target
Before=network-pre.target

[Service]
ExecStart=/usr/lib/arch-hardening-script/spoof-mac-addresses
Type=oneshot
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateTmp=true
MemoryDenyWriteExecute=true
NoNewPrivileges=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET
SystemCallArchitectures=native
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
EOF

      # Enables systemd service.
      systemctl enable macspoof.service
    elif [ "${which_mac_spoofer}" = "NetworkManager" ]; then
        # Installs networkmanager if it isn't already installed.
        if ! pacman -Qq networkmanager &>/dev/null; then
          read -r -p "NetworkManager is not installed. Install it now? (y/n) " install_networkmanager
          if [ "${install_networkmanager}" = "y" ]; then
            pacman -S --noconfirm -q networkmanager
          fi
        fi

        # Randomize MAC address with networkmanager.
        cat <<EOF > /etc/NetworkManager/conf.d/rand_mac.conf
[connection-mac-randomization]
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random
EOF
    fi
  fi
}

configure_umask() {
  ## Set a more restrictive umask.
  read -r -p "Set a more restrictive umask? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#umask) (y/n) " umask
  if [ "${umask}" = "y" ]; then
    echo "umask 0077" > /etc/profile.d/umask.sh
  fi
}

install_usbguard() {
  ## USBGuard.
  read -r -p "Install USBGuard? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#usbs) (y/n) " usbguard
  if [ "${usbguard}" = "y" ]; then
    # Checks if usbguard is already installed.
    if ! pacman -Qq usbguard &>/dev/null; then
      # Installs usbguard.
      pacman -S --noconfirm -q usbguard
    fi
  fi
}

blacklist_dma() {
  ## Blacklist thunderbolt and firewire kernel modules.
  read -r -p "Blacklist Thunderbolt and Firewire? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#thunderbolt_and_firewire) (y/n) " thunderbolt_firewire
  if [ "${thunderbolt_firewire}" = "y" ]; then
    echo "install firewire-core /bin/true
install thunderbolt /bin/true" > /etc/modprobe.d/blacklist-dma.conf
  fi
}

disable_coredumps() {
  ## Core Dumps
  read -r -p "Disable coredumps? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#core_dumps) (y/n) " coredumps
  if [ "${coredumps}" = "y" ]; then
    # Disables coredumps via sysctl.
    echo "kernel.core_pattern=|/bin/false" > /etc/sysctl.d/disable_coredumps.conf

    # Make coredump drop-in directory if it doesn't already exist.
    if ! [ -d /etc/systemd/coredump.conf.d ]; then
      mkdir /etc/systemd/coredump.conf.d
    fi

    # Disables coredumps via systemd.
    echo "[Coredump]
Storage=none" > /etc/systemd/coredump.conf.d/disable_coredumps.conf

    # Disables coredumps via limits.
    echo "* hard core 0" >> /etc/security/limits.conf

    # Prevents SUID processes from creating coredumps if not already set.
    if ! sysctl fs.suid_dumpable | grep "0" &>/dev/null; then
      echo "fs.suid_dumpable=0" > /etc/sysctl.d/suid_dumpable.conf
    fi
  fi
}

microcode_updates() {
  ## Microcode updates.
  read -r -p "Install microcode updates? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#microcode) (y/n) " microcode
  if [ "${microcode}" = "y" ]; then
    # Checks which CPU is being used.
    if grep 'AMD' /proc/cpuinfo >/dev/null; then
      # Install AMD ucode.
      if ! pacman -Qq amd-ucode &>/dev/null; then
        pacman -S --noconfirm -q amd-ucode
      fi

      cpu_manufacturer="amd"
    elif grep 'Intel' /proc/cpuinfo >/dev/null; then
      # Install Intel ucode.
      if ! pacman -Qq intel-ucode &>/dev/null; then
        pacman -S --noconfirm -q intel-ucode
      fi

      cpu_manufacturer="intel"
    fi

    if [ "${use_grub}" = "y" ]; then
      # Update GRUB configuration.
      grub-mkconfig -o /boot/grub/grub.cfg
    elif [ "${use_syslinux}" = "y" ]; then
      # Get current initrd configuration.
      current_initrd=$(grep -v "Fallback" /boot/syslinux/syslinux.cfg | grep -C 3 "MENU LABEL Arch Linux" | grep "INITRD")

      # Update syslinux configuration.
      sed -i "s|${current_initrd}|${current_initrd},../${cpu_manufacturer}-ucode.img|" /boot/syslinux/syslinux.cfg
    fi
  fi
}

disable_ntp() {
  ## NTP
  read -r -p "Disable NTP? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#ntp) (y/n) " ntp
  if [ "${ntp}" = "y" ]; then
    # Uninstalls NTP clients
    for ntp_client in ntp openntpd ntpclient
    do
      if pacman -Qq "${ntp_client}" &>/dev/null; then
        pacman -Rn --noconfirm ${ntp_client}
      fi
    done

    # Disables NTP
    timedatectl set-ntp 0
    systemctl mask systemd-timesyncd.service
  fi
}

ipv6_privacy_extensions() {
  ## IPv6 Privacy Extensions
  if ! [ "${disable_ipv6}" = "y" ]; then
    read -r -p "Do you want to enable IPv6 privacy extensions? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#ipv6_privacy) (y/n) " ipv6_privacy
    if [ "${ipv6_privacy}" = "y" ]; then
      # Enable IPv6 privacy extensions via sysctl.
      echo "net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.use_tempaddr=2" > /etc/sysctl.d/ipv6_privacy.conf

      # Get list of network interfaces. Excludes loopback and virtual machine interfaces.
      net_interfaces=$(ls /sys/class/net | grep -v 'lo' | grep -v 'tun0' | grep -v "virbr")

      # Add them to ipv6_privacy.conf.
      for i in ${net_interfaces}
      do
        echo "net.ipv6.conf.${i}.use_tempaddr=2" >> /etc/sysctl.d/ipv6_privacy.conf
      done

      ## Check for NetworkManager.
      if pacman -Qq networkmanager &>/dev/null; then
        # Enable IPv6 privacy extensions for NetworkManager.
        read -r -p "Enable IPv6 privacy extensions for NetworkManager? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#ipv6_networkmanager) (y/n)" networkmanager
        if [ "${networkmanager}" = "y" ]; then
          echo "[connection]
ipv6.ip6-privacy=2" >> /etc/NetworkManager/NetworkManager.conf
        fi
      fi

      ## Check for systemd-networkd.
      if systemctl is-active systemd-networkd.service >/dev/null 2>&1; then
        # Enable IPv6 privacy extensions for systemd-networkd.
        read -r -p "Enable IPv6 privacy extensions for systemd-networkd? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#ipv6_systemd-networkd) (y/n) " systemd-networkd
        if [ "${systemd-networkd}" = "y" ]; then
          echo "[Network]
IPv6PrivacyExtensions=kernel" > /etc/systemd/network/ipv6_privacy.conf
        fi
      fi
    fi
  fi
}

blacklist_uncommon_network_protocols() {
  ## Blacklist uncommon network protocols.
  read -r -p "Blacklist uncommon network protocols? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#uncommon_protocols) (y/n) " blacklist_net_protocols
  if [ "${blacklist_net_protocols}" = "y" ]; then
    cat <<EOF > /etc/modprobe.d/uncommon-network-protocols.conf
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install n-hdlc /bin/true
install ax25 /bin/true
install netrom /bin/true
install x25 /bin/true
install rose /bin/true
install decnet /bin/true
install econet /bin/true
install af_802154 /bin/true
install ipx /bin/true
install appletalk /bin/true
install psnap /bin/true
install p8023 /bin/true
install llc /bin/true
install p8022 /bin/true
EOF
  fi
}

disable_uncommon_filesystems() {
  ## Disable mounting of uncommon filesystems.
  read -r -p "Disable mounting of uncommon filesystems? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#uncommon_filesystems) (y/n) " blacklist_filesystems
  if [ "${blacklist_filesystems}" = "y" ]; then
    cat <<EOF > /etc/modprobe.d/uncommon-filesystems.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
  fi
}

more_entropy() {
  ## Gather more entropy.
  read -r -p "Do you want to gather more entropy? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#entropy) (y/n) " gather_more_entropy
  if [ "${gather_more_entropy}" = "y" ]; then
    # Enable haveged.
    if ! pacman -Qq haveged &>/dev/null; then
      read -r -p "Do you want to install and enable haveged? (y/n) " enable_haveged
      if [ "${enable_haveged}" = "y" ]; then
        pacman -S --noconfirm -q haveged
        systemctl enable haveged.service
      fi
    fi

    # Install jitterentropy.
    if ! pacman -Qq jitterentropy &>/dev/null; then
      read -r -p "Do you want to install jitterentropy? (y/n) " install_jitterentropy
      if [ "${install_jitterentropy}" = "y" ]; then
        pacman -S --noconfirm -q jitterentropy
      fi
    fi
  fi
}

webcam_and_microphone() {
  ## Block the webcam and microphone.
  read -r -p "Do you want to blacklist the webcam kernel module? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#microphones_and_webcams) (y/n) " blacklist_webcam
  if [ "${blacklist_webcam}" = "y" ]; then
    # Blacklist the webcam kernel module.
    echo "install uvcvideo /bin/true" > /etc/modprobe.d/blacklist-webcam.conf
  fi

  read -r -p "Do you want to blacklist the microphone and speaker kernel module? (see: https://theprivacyguide1.github.io/linux_hardening_guide.html#microphones_and_webcams) (y/n) " blacklist_mic
  if [ "${blacklist_mic}" = "y" ]; then
    # Blacklist the microphone and speaker kernel module.
    mic_modules=$(awk '{print $2}' /proc/asound/modules | awk '!x[$0]++')

    # Accounts for multiple sound cards.
    for i in ${mic_modules}
    do
      echo "install ${i} /bin/true" >> /etc/modprobe.d/blacklist-mic.conf
    done
  fi
}

ending() {
  ## Reboot
  read -r -p "Reboot to apply all of the changes? (y/n) " reboot
  if [ "${reboot}" = "y" ]; then
    reboot
  fi
}

read -r -p "Start? (y/n) " start
if [ "${start}" = "n" ]; then
  exit 1
elif ! [ "${start}" = "y" ]; then
  echo "You did not enter a correct character."
  exit 1
fi

script_checks
sysctl_hardening
boot_parameter_hardening
#hidepid
disable_nf_conntrack_helper
#install_linux_hardened
apparmor
get_firejail
restrict_root
firewall
setup_tor
configure_hostname
block_wireless_devices
mac_address_spoofing
configure_umask
install_usbguard
blacklist_dma
disable_coredumps
microcode_updates
disable_ntp
ipv6_privacy_extensions
blacklist_uncommon_network_protocols
disable_uncommon_filesystems
more_entropy
webcam_and_microphone
ending
