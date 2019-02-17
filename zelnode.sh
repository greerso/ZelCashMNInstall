#!/bin/bash
# Author: Greerso https://github.com/greerso
# Steemit:  https://steemit.com/@greerso
#
# BTC 1BzrkEMSF4aXBtZ19DhVf8KMPVkXjXaAPG
# ETH 0x0f64257fAA9E5E36428E5BbB44C9A2aE3A055577
# ZEC t1QCnCQstdgvZ5v3P9sZbeT9ViJd2pDfNBL
# ZEL t1Q7AvoPtMz9nWkm6adAeJF8GL75zjWYWLU

# ==============================================================================
# WORK IN PROGRESS
# ==============================================================================


# ==============================================================================
# Variables
# ==============================================================================
# Project Specific
project_name="zelcash"
project_github_repo="zelcash/zelcash"
github_release_keyword=linux
declare -A node_req=(
    [basic_stake]="10000"
    [super_stake]="25000"
    [bamf_stake]="100000"
    [basic_cores]="2"
    [super_cores]="4"
    [bamf_cores]="8"
    [basic_ram]="4G"
    [super_ram]="8G"
    [bamf_ram]="32G"
    [basic_ssd]="50G"
    [super_ssd]="150G"
    [bamf_ssd]="600G"
	)
rpc_port="17654"
p2p_port="17652"
#
export NEWT_COLORS=''
rpc_user="${project_name}_$(head -c 8 /dev/urandom | base64)"
rpc_password="$(head -c 32 /dev/urandom | base64)"
linux_user=$(who -m | awk '{print $1;}')
linux_user_pw="$(head -c 32 /dev/urandom | base64)"
public_ip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
internal_ip="$(hostname -I)"
hostname="$(cat /etc/hostname)"
ssh_port=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
wallet_location="${HOME}/.${project_name}"
daemon_binary="${project_name}d"
project_cli="${project_name}-cli"
project_logo=""
wt_backtitle="$project_name Masternode Installer"
wt_title="Installing the $project_name Masternode..."
declare mn_alias
declare mn_priv_key
declare collateral_output_txid
declare collateral_output_index
declare -a base_pkgs=(\
    apt-transport-https \
    ca-certificates \
    curl \
    htop \
    jq \
    libevent-dev \
    lsb-release \
    software-properties-common \
    unzip \
    wget \
    whiptail)
declare -a project_pkgs=(\
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-chrono-dev \
    libboost-program-options-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libdb-dev \
    libdb++-dev
    libzmq3-dev \
    libminiupnpc-dev)
# ------------------------------------------------------------------------------

# ==============================================================================
# Functions
# ==============================================================================

# Silence
# Use 'stfu command args...'
stfu() {
  "$@" >/dev/null 2>&1
}

# Use 'copy_text "text to display"'
text_to_copy() {
    clear
    echo
    echo
    echo "# ===========Start copy text AFTER this line==========="
    echo -e "$@"
    echo "# ===========Stop copy text BEFORE this line==========="
    echo
    echo "DO NOT USE CTRL+C TO COPY, IN LINUX THIS WILL CANCEL THE SCRIPT."
    echo "INSTEAD USE THE EDIT MENU IN YOUR TERMINAL APPLICATION AND CHOOSE THE COPY ITEM"
    echo "IN PUTTY THE ACT OF SELECTING TEXT AUTOMATICALLY COPIES IT"
    read -n 1 -s -r -p "Press any key to continue..."
    clear
}

# Use 'user_in_group user group'
user_in_group() {
    groups $1 | grep -q "\b$2\b"
}

count_lines() {
  fmt -w "$2" <<<"$1" | wc -l
}

# infobox TEXT
infobox() {
	#count lines, then count characters on each line and multiply line by factor of width
    base_lines=4
    wt_width=72
    wt_height=$(count_lines "$@" $wt_width)
    wt_size="$wt_height $wt_width"
    TERM=ansi whiptail \
    --infobox "$@" \
    --backtitle "$wt_backtitle" \
    --title "$wt_title" \
    $wt_size
}

# msgbox TEXT
msgbox() {
    base_lines=10
    wt_width=72
    wt_height=$(count_lines "$@" $wt_width)
    wt_size="$wt_height $wt_width"
    TERM=ansi whiptail \
    --msgbox "$@" \
    --backtitle "$wt_backtitle" \
    --title "$wt_title" \
    $wt_size
}

# inputbox TEXT
inputbox() {
    base_lines=10
    wt_width=72
    wt_height=$(count_lines "$@" $wt_width)
    wt_size="$wt_height $wt_width"
    TERM=ansi whiptail \
    --inputbox "$@" \
    --backtitle "$wt_backtitle" \
    --title "$wt_title" \
    3>&1 1>&2 2>&3 \
    $wt_size
}

# yesnobox TEXT
yesnobox() {
    base_lines=10
    wt_width=72
    wt_height=$(count_lines "$@" $wt_width)
    wt_size="$wt_height $wt_width"
TERM=ansi whiptail \
--yesno "$@" \
--backtitle "$wt_backtitle" \
--title "$wt_title" \
3>&1 1>&2 2>&3 \
$wt_size
}

min_ubuntu() {
    ubuntu_ver=$(lsb_release -rs)
    ubuntu_min_ver="16.04"
    min_ubuntu=$(bc -l <<< "$ubuntu_ver < $ubuntu_min_ver")
    if $min_ubuntu ; then
    msgbox "At least Ubuntu $ubuntu_min_ver is required, you have $ubuntu_ver.  Exiting..."
    exit 1
    fi
}

auth_sudo() {
    if [ "$(id -nu)" != "root" ]; then
    sudo -k
    password=$(whiptail --backtitle "$project_name Masternode Installer" --title "Authentication required" --passwordbox "Installing $project_name requires root privilege. Please authenticate to begin the installation.\n[sudo] password for user $USER:" 12 50 3>&2 2>&1 1>&3-)
    exec sudo -E -S -p '' "$0" "$@" <<< "$password"
    fi
}

daemon_running() {
    if [ -n "$(pidof $daemon_binary)" ]; then
    msgbox "The $project_name daemon is already running."
    # what user is running the daemon
    # where is the wallet stored
    # is systemd controlling the daemon or was it started from a cron job?
    # check for updates
    exit 1
    fi
}

#enable_sshkeys() {
# did user login using sshkeys?
# is user root user?
# does user want to use this account to run daemon
#}

pre_checks() {
	min_ubuntu
	daemon_running
	authsudo
}

install_packages() {
apt update
apt-get -y install aptitude
aptitude -yq3 update
aptitude -yq3 full-upgrade
# add an if exists to each of the following
aptitude -yq3 install ${base_pkgs[@]} $@
aptitude -yq3 install ${project_pkgs[@]}

# Add bitcoin repo for ancient version of libdb if wallet requires.
# stfu add-apt-repository -y ppa:bitcoin/bitcoin
# stfu apt update
# stfu aptitude -yq3 install \
#   libdb4.8-dev \
#   libdb4.8++-dev
}

change_hostname() {
hostname=$(hostname)
if [ -z "$1" ]; then
newhostname=$(inputbox "Your hostname is $hostname,  please enter a new hostname then press ok.")
else
newhostname="$1"
fi
sed -i "s|$hostname|$newhostname|1" /etc/hostname
if grep -q "$hostname" /etc/hosts; then
sed -i "s|$hostname|$newhostname|1" /etc/hosts
else
echo "127.0.0.1 $newhostname" >> /etc/hosts
fi
}

create_swap() {
total_mem=$(free -m | awk '/^Mem:/{print $2}')
total_swap=$(free -m | awk '/^Swap:/{print $2}')
total_m=$(($total_mem + $total_swap))
if [ $total_m -lt 4000 ]; then
if ! grep -q '/swapfile' /etc/fstab ; then
fallocate -l 4G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
fi
}

create_user() {
if [ -z "$1" ]; then
USERNAME=$(inputbox "Please enter the new user name")
else
USERNAME=$1
fi
user_password=$(inputbox "Please enter a password for '${USERNAME}'")
adduser --gecos "" --disabled-password --quiet "${USERNAME}"
echo "${USERNAME}:${user_password}" | chpasswd
# Add user to sudoers
usermod -a -G sudo "${USERNAME}"
linux_user=${USERNAME}
wallet_location="$(eval echo "~${USERNAME}")/.${project_name}"
# add option to ask instead of adding to sudoers by default
# add a loop to add more users  
}

iamroot() {
	if [ "$linux_user" == "root" ]; then
	wt_title="I AM ROOT" 
	if (yesnobox "You are logged into your server as root.\n\nIt is not reccomended to install and run your masternode as root. Would you like to create a normal user?"); then
	create_user
	fi
fi
}

unattended-upgrades() {
apt-get -y install unattended-upgrades >/dev/null 2>&1
autoUpdateCommands=(
's|\"\${distro_id}:\${distro_codename}\";|// \"\${distro_id}:\${distro_codename}\";|'
's|\"\${distro_id}ESM:\${distro_codename}\";|// \"\${distro_id}ESM:\${distro_codename}\";|'
)
for autoUpdateCommand in "${autoUpdateCommands[@]}"; do
sed -i "$autoUpdateCommand" /etc/apt/apt.conf.d/50unattended-upgrades
done
if ! grep -q "APT::Periodic::Unattended-Upgrade \"1\" ;" /etc/apt/apt.conf.d/10periodic; then
echo "APT::Periodic::Unattended-Upgrade \"1\" ;" >> /etc/apt/apt.conf.d/10periodic
fi
}

harden_ssh() {
# Set ssh port
ssh_port=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
if [ $ssh_port -eq 22 ] ; then
NEW_ssh_port=$(inputbox "SSH is currently running on $NEW_ssh_port.  Botnets scan are constantly scanning this port.  Enter a new port or press enter to accept port 2222" )
fi
if grep -q Port /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})Port)( *)?(.*)|Port $NEW_ssh_port|1" /etc/ssh/sshd_config
else
echo "Port $NEW_ssh_port" >> /etc/ssh/sshd_config
fi
# Disable root user ssh login
# Make sure that you have a normal user before doing this
if grep -q PermitRootLogin /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})PermitRootLogin)( *)?(.*)|PermitRootLogin no|1" /etc/ssh/sshd_config
else
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi
# Disable the use of passwords with ssh
# Add ssh-key for remote user to linux_user .ssh/allowed_keys
if grep -q passwordAuthentication /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})passwordAuthentication)( *)?(.*)|passwordAuthentication no|1" /etc/ssh/sshd_config
else
echo "passwordAuthentication no" >> /etc/ssh/sshd_config
fi
# Restart the ssh daemon
systemctl restart sshd
}

setup_ufw() {
    ssh_port=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
    allowed_ports=[$@]
    remote_ip=$(echo -e $SSH_CLIENT | awk '{ print $1}')
    
    if ! [ -f /etc/ufw/ufw.conf ]; then
        apt-get -y install ufw
    fi
    
    # Open all outgoing ports, block all incoming ports then open port $ssh_port for ssh.
    ufw default allow outgoing
    ufw default deny incoming
    
    # Open ports
    ufw limit $ssh_port/tcp comment 'ssh port'
    ufw allow $p2p_port/tcp comment 'mn p2p port'
    ufw allow $rpc_port/tcp comment 'mn rpc port'
    allow all ports from $remote_ip
    # Enable the firewall
    ufw --force enable
}

setup_fail2ban() {
remote_ip=$(echo -e $SSH_CLIENT | awk '{ print $1}')
fqdn="$(hostname -f)"
ssh_port=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
jail_local="[blacklist]\nenabled = true\nlogpath  = /var/log/fail2ban.*\nbanaction = blacklist\nbantime  = 31536000   \; 1 year\nfindtime = 31536000   \; 1 year\nmaxretry = 10\n\n[Definition]\nloglevel = INFO\nlogtarget = /var/log/fail2ban.log\nsyslogsocket = auto\nsocket = /var/run/fail2ban/fail2ban.sock\npidfile = /var/run/fail2ban/fail2ban.pid\ndbfile = /var/lib/fail2ban/fail2ban.sqlite3\ndbpurgeage = 86400"
jail_local=$(echo -e $jail_local)

if [ ! -f /etc/fail2ban/jail.local ]; then
apt -y install fail2ban
cat <<EOF > /etc/fail2ban/jail.local
$jail_local
EOF
fi

sed -i -e 's|ignoreip = 127.0.0.1/8|ignoreip = $remote_ip|g' /etc/fail2ban/jail.local
# jail.local:
# [sshd]
# action = %(action_)s
# smtp.py[host="host:25", user="my-account", password="my-pwd", sender="sender@example.com", dest="example@example.com", name="%(__name__)s"]
# sed -i -e 's|destemail = root@localhost|destemail = me@myemail.com |g' /etc/fail2ban/jail.local
# sed -i -e 's|sender = root@localhost|sender = fail2ban@$fqdn\nsendername = Fail2Ban|g' /etc/fail2ban/jail.local
# sed -i -e 's|mta = sendmail|mta = mail|g' /etc/fail2ban/jail.local
sed -i -e 's|action = %(action_)s|action = %(action_mwl)s|g' /etc/fail2ban/jail.local
sed -i -e 's|= ssh|= $ssh_port|g' /etc/fail2ban/jail.local

#create an action for repeat offenders from mitchellkrogza/Fail2Ban-Blacklist

cat <<EOF >> /etc/fail2ban/action.d/blacklist.conf
# /etc/fail2ban/action.d/blacklist.conf
# Fail2Ban Blacklist for Repeat Offenders (action.d)
# Version: 1.0
# GitHub: https://github.com/mitchellkrogza/Fail2Ban-Blacklist-JAIL-for-Repeat-Offenders-with-Perma-Extended-Banning
# Tested On: Fail2Ban 0.91
# Server: Ubuntu 16.04
# Firewall: IPTables
#

[INCLUDES]
before = iptables-common.conf


[Definition]
# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#

actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -j f2b-<name>
              # Sort and Check for Duplicate IPs in our text file and Remove Them
              sort -u /etc/fail2ban/ip.blacklist -o /etc/fail2ban/ip.blacklist
              # Persistent banning of IPs reading from our ip.blacklist text file
              # and adding them to IPTables on our jail startup command
              cat /etc/fail2ban/ip.blacklist | while read IP; do iptables -I f2b-<name> 1 -s $IP -j DROP; done

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#

actionstop = <iptables> -D <chain> -p <protocol> -j f2b-<name>
             <iptables> -F f2b-<name>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j DROP
# Add the new IP ban to our ip.blacklist file
echo '<ip>' >> /etc/fail2ban/ip.blacklist

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j DROP
# Remove IP from our ip.blacklist file
sed -i -e '/<ip>/d' /etc/fail2ban/ip.blacklist

[Init]
EOF

cat <<EOF >> /etc/fail2ban/filter.d/blacklist.conf
# /etc/fail2ban/filter.d/blacklist.conf
# Fail2Ban Blacklist for Repeat Offenders (filter.d)
#
# Version: 1.0
# GitHub: https://github.com/mitchellkrogza/Fail2Ban-Blacklist-JAIL-for-Repeat-Offenders-with-Perma-Extended-Banning
# Tested On: Fail2Ban 0.91
# Server: Ubuntu 16.04
# Firewall: IPTables
#

[INCLUDES]

# Read common prefixes. If any customizations available -- read them from
# common.local
before = common.conf

[Definition]

_daemon = fail2ban\.actions\s*

# The name of the jail that this filter is used for. In jail.conf, name the 
# jail using this filter 'blacklist', or change this line!
_jailname = blacklist

failregex = ^(%(__prefix_line)s| %(_daemon)s%(__pid_re)s?:\s+)NOTICE\s+\[(?!%(_jailname)s\])(?:.*)\]\s+Ban\s+<HOST>\s*$

ignoreregex = 

[Init]

journalmatch = _SYSTEMD_UNIT=fail2ban.service PRIORITY=5
EOF

#
# Secure shared memory
#

cat <<EOF >> /etc/fstab

tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0
EOF

# Harden the networking layer

# Prevent source routing of incoming packets
# enable Spoof protection
if grep -q net.ipv4.conf.default.rp_filter /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.default.rp_filter)( *)?(.*)|net.ipv4.conf.default.rp_filter = 1|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.conf
fi

if grep -q net.ipv4.conf.all.rp_filter /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.rp_filter)( *)?(.*)|net.ipv4.conf.all.rp_filter=1|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
fi

# enable TCP/IP SYN cookies
if grep -q net.ipv4.tcp_syncookies /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.tcp_syncookies)( *)?(.*)|net.ipv4.tcp_syncookies=1|1" /etc/sysctl.conf
else
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
fi

# Ignore ICMP broadcat requests
if grep -q net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.icmp_echo_ignore_broadcasts)( *)?(.*)|net.ipv4.icmp_echo_ignore_broadcasts=1|1" /etc/sysctl.conf
else
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
fi

# Disable source packet routing
if grep -q net.ipv4.conf.all.accept_source_route /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.accept_source_route)( *)?(.*)|net.ipv4.conf.all.accept_source_route = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv6.conf.all.accept_source_route /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv6.conf.all.accept_source_route)( *)?(.*)|net.ipv6.conf.all.accept_source_route = 0|1" /etc/sysctl.conf
else
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv4.conf.default.accept_source_route /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.default.accept_source_route)( *)?(.*)|net.ipv4.conf.default.accept_source_route = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv6.conf.default.accept_source_route /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv6.conf.default.accept_source_route)( *)?(.*)|net.ipv6.conf.default.accept_source_route = 0|1" /etc/sysctl.conf
else
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
fi

# Ignore send redirects
if grep -q net.ipv4.conf.all.send_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.send_redirects)( *)?(.*)|net.ipv4.conf.all.send_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv4.conf.default.send_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.default.send_redirects)( *)?(.*)|net.ipv4.conf.default.send_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
fi

# Log Martians
if grep -q net.ipv4.conf.all.log_martians /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.log_martians)( *)?(.*)|net.ipv4.conf.all.log_martians = 1|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
fi

# Bogus error responses
if grep -q net.ipv4.icmp_ignore_bogus_error_responses /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.icmp_ignore_bogus_error_responses)( *)?(.*)|net.ipv4.icmp_ignore_bogus_error_responses = 1|1" /etc/sysctl.conf
else
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
fi

# Ignore ICMP redirects
if grep -q net.ipv4.conf.all.accept_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.accept_redirects)( *)?(.*)|net.ipv4.conf.all.accept_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv6.conf.all.accept_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv6.conf.all.accept_redirects)( *)?(.*)|net.ipv6.conf.all.accept_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv4.conf.default.accept_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.default.accept_redirects)( *)?(.*)|net.ipv4.conf.default.accept_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv6.conf.default.accept_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv6.conf.default.accept_redirects)( *)?(.*)|net.ipv6.conf.default.accept_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
fi

# Ignore Directed pings
if grep -q net.ipv4.icmp_echo_ignore_all /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.icmp_echo_ignore_all)( *)?(.*)|net.ipv4.icmp_echo_ignore_all = 1|1" /etc/sysctl.conf
else
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
fi

# restart the service
sysctl -p.

systemctl restart fail2ban

}

# download_binaries project_name project_github_repo
download_binaries() {
if [[ $1 -eq 'testnet' ]]; then
	wget -P /usr/local/bin https://zelcore.io/downloads/nodes/testnetv6/zelcash-cli -q
    wget -P /usr/local/bin https://zelcore.io/downloads/nodes/testnetv6/zelcashd -q
    chmod +x /usr/local/bin/zelcash* else
    github_bin_url="$(curl -sSL https://api.github.com/repos/${project_github_repo}/releases/latest | jq -r ".assets[] | select(.name | test(\"$github_release_keyword\")) | .browser_download_url")"    
    curl -sSL "$github_bin_url" | tar xvz -C /usr/local/bin/
fi
}

wallet_configs() {
mkdir -p $wallet_location
cat <<EOF > $wallet_location/zelnode.conf
$masternode_conf
EOF
server_wallet_conf=$(echo -e $server_wallet_conf)
cat <<EOF > $wallet_location/${project_name}.conf
$server_wallet_conf
EOF
chown -R $linux_user $wallet_location
}

daemon_service() {
daemon_service=$(echo -e $daemon_service)
cat <<EOF > /etc/systemd/system/$daemon_binary.service
$daemon_service
EOF
chmod 755 /etc/systemd/system/$daemon_binary.service
systemctl daemon-reload
systemctl enable $daemon_binary
systemctl restart $daemon_binary
}

masternode_sync() {
echo "Syncing Masternode..."
until ${daemon_binary} masternode debug | grep -m 1 "Masternode successfully started"; do
echo "."
sleep 3
done
}

install_checkblocks() {
check_blocks="previousBlock=$(cat wallet_location/blockcount)\ncurrentBlock=$(${project_cli} getblockcount)\n\n${project_cli} getblockcount > wallet_location/blockcount\n\nif [ $previousBlock == $currentBlock ]; then\n\nsudo systemctl restart ${daemon_binary}\n\nfi"
check_blocks=$(echo -e $check_blocks)
echo "%sudo ALL=NOPASSWD: /bin/systemctl restart ${daemon_binary}.service" >> /etc/sudoers
cb_cron="*/30 * * * * ${linux_user} sudo ${wallet_location}/checkdaemon.sh >> ${wallet_location}/cron.log"
cat <<EOF > $wallet_location/checkblocks.sh
$check_blocks
EOF
cat <<EOF > /etc/cron.d/${project_name}-checkdaemon
$cb_cron
EOF
chown -R ${linux_user}:${linux_user} $wallet_location
chmod +x ${wallet_location}/checkblocks.sh
}

fetch_params() {
set -eu

PARAMS_DIR="$wallet_location/../.zcash-params"

SPROUT_PKEY_NAME='sprout-proving.key'
SPROUT_VKEY_NAME='sprout-verifying.key'
SAPLING_SPEND_NAME='sapling-spend.params'
SAPLING_OUTPUT_NAME='sapling-output.params'
SAPLING_SPROUT_GROTH16_NAME='sprout-groth16.params'

SPROUT_URL="https://z.cash/downloads"
SPROUT_IPFS="/ipfs/QmZKKx7Xup7LiAtFRhYsE1M7waXcv9ir9eCECyXAFGxhEo"

SHA256CMD="$(command -v sha256sum || echo shasum)"
SHA256ARGS="$(command -v sha256sum >/dev/null || echo '-a 256')"

WGETCMD="$(command -v wget || echo '')"
IPFSCMD="$(command -v ipfs || echo '')"
CURLCMD="$(command -v curl || echo '')"

# fetch methods can be disabled with ZC_DISABLE_SOMETHING=1
ZC_DISABLE_WGET="${ZC_DISABLE_WGET:-}"
ZC_DISABLE_IPFS="${ZC_DISABLE_IPFS:-}"
ZC_DISABLE_CURL="${ZC_DISABLE_CURL:-}"

function fetch_wget {
    if [ -z "$WGETCMD" ] || ! [ -z "$ZC_DISABLE_WGET" ]; then
        return 1
    fi

    local filename="$1"
    local dlname="$2"

    cat <<EOF

Retrieving (wget): $SPROUT_URL/$filename
EOF

    wget \
        --progress=dot:giga \
        --output-document="$dlname" \
        --continue \
        --retry-connrefused --waitretry=3 --timeout=30 \
        "$SPROUT_URL/$filename"
}

function fetch_ipfs {
    if [ -z "$IPFSCMD" ] || ! [ -z "$ZC_DISABLE_IPFS" ]; then
        return 1
    fi

    local filename="$1"
    local dlname="$2"

    cat <<EOF

Retrieving (ipfs): $SPROUT_IPFS/$filename
EOF

    ipfs get --output "$dlname" "$SPROUT_IPFS/$filename"
}

function fetch_curl {
    if [ -z "$CURLCMD" ] || ! [ -z "$ZC_DISABLE_CURL" ]; then
        return 1
    fi

    local filename="$1"
    local dlname="$2"

    cat <<EOF

Retrieving (curl): $SPROUT_URL/$filename
EOF

    curl \
        --output "$dlname" \
        -# -L -C - \
        "$SPROUT_URL/$filename"

}

function fetch_failure {
    cat >&2 <<EOF

Failed to fetch the Zcash zkSNARK parameters!
Try installing one of the following programs and make sure you're online:

 * ipfs
 * wget
 * curl

EOF
    exit 1
}

function fetch_params {
    local filename="$1"
    local output="$2"
    local dlname="${output}.dl"
    local expectedhash="$3"

    if ! [ -f "$output" ]
    then
        for method in wget ipfs curl failure; do
            if "fetch_$method" "$filename" "$dlname"; then
                echo "Download successful!"
                break
            fi
        done

        "$SHA256CMD" $SHA256ARGS -c <<EOF
$expectedhash  $dlname
EOF

        # Check the exit code of the shasum command:
        CHECKSUM_RESULT=$?
        if [ $CHECKSUM_RESULT -eq 0 ]; then
            mv -v "$dlname" "$output"
        else
            echo "Failed to verify parameter checksums!" >&2
            exit 1
        fi
    fi
}

# Use flock to prevent parallel execution.
function lock() {
    local lockfile=/tmp/fetch_params.lock
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if shlock -f ${lockfile} -p $$; then
            return 0
        else
            return 1
        fi
    else
        # create lock file
        eval "exec 200>$lockfile"
        # acquire the lock
        flock -n 200 \
            && return 0 \
            || return 1
    fi
}

function exit_locked_error {
    echo "Only one instance of fetch-params.sh can be run at a time." >&2
    exit 1
}

function main() {

    lock fetch-params.sh \
    || exit_locked_error

    cat <<EOF
Zelcash - fetch-params.sh

This script will fetch the Zcash zkSNARK parameters and verify their
integrity with sha256sum.

If they already exist locally, it will exit now and do nothing else.
EOF

    # Now create PARAMS_DIR and insert a README if necessary:
    if ! [ -d "$PARAMS_DIR" ]
    then
        mkdir -p "$PARAMS_DIR"
        README_PATH="$PARAMS_DIR/README"
        cat >> "$README_PATH" <<EOF
This directory stores common Zcash zkSNARK parameters. Note that it is
distinct from the daemon's -datadir argument because the parameters are
large and may be shared across multiple distinct -datadir's such as when
setting up test networks.
EOF

        # This may be the first time the user's run this script, so give
        # them some info, especially about bandwidth usage:
        cat <<EOF
The complete parameters are currently just under 1.7GB in size, so plan 
accordingly for your bandwidth constraints. If the Sprout parameters are
already present the additional Sapling parameters required are just under 
800MB in size. If the files are already present and have the correct 
sha256sum, no networking is used.

Creating params directory. For details about this directory, see:
$README_PATH

EOF
    fi

    cd "$PARAMS_DIR"

    # Sprout parameters:
    fetch_params "$SPROUT_PKEY_NAME" "$PARAMS_DIR/$SPROUT_PKEY_NAME" "8bc20a7f013b2b58970cddd2e7ea028975c88ae7ceb9259a5344a16bc2c0eef7"
    fetch_params "$SPROUT_VKEY_NAME" "$PARAMS_DIR/$SPROUT_VKEY_NAME" "4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82"

    # Sapling parameters:
    fetch_params "$SAPLING_SPEND_NAME" "$PARAMS_DIR/$SAPLING_SPEND_NAME" "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13"
    fetch_params "$SAPLING_OUTPUT_NAME" "$PARAMS_DIR/$SAPLING_OUTPUT_NAME" "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"
    fetch_params "$SAPLING_SPROUT_GROTH16_NAME" "$PARAMS_DIR/$SAPLING_SPROUT_GROTH16_NAME" "b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50"
}

main
rm -f /tmp/fetch_params.lock
#exit 0
}

# ------------------------------------------------------------------------------

# ==============================================================================
# Pre-checks
# ==============================================================================
pre_checks
# ------------------------------------------------------------------------------

# ==============================================================================
# Setup dialogs
# ==============================================================================
#- Harden SSH security
#  - Change SSH from port 22
#  - Disable root logon
#  - Require ssh-keys
declare -a install_options=("
Base server install
 - Create swap space for a low ram vps
 - Add a non-root user
 - Configure automatic security updates for Ubuntu
 - Install and configure UFW Firewall
  - Allow all outbound traffic
  - Deny all inbound traffic
  - Allow inbound P2P for Masternode and SSH
  - Whitelist installer ip address
 - Install and configure Fail2Ban IDS
 - Autoblock repeat offenders from public blacklist
Masternode install
- Prompted install
- Automatically detect Client and Host ip addresses
- Automatically generate RPC User and secure password.
- Download latest version from Github API
")
declare -A install_steps=(
    [installing]="Installing packages required for setup...\n(this could take a few minutes)"
    [install_dependencies]="This script will walk you through the following:\n\n${install_options}\n\nYou will need:\n- A Swing wallet with at least ${node_req[basic_stake]} coins and to know how to copy/paste."
    [create_nodekey]="Launch the control wallet (wallet on your everyday PC, not on this VPS).\nOpen CMD.\nChange directory to the directory containing zelcash-cli.\nPaste the command\n\nzelcash-cli createzelnodekey\n\n. This will be the private key for the ZelNode, *not* your collateral/rewards Private Key."
    [choose_alias]="Choose an alias for your masternode, for example MN1, then enter it here"
    [collateral_address]="Back in the CMD window on your PC paste the following command to get a public address to send the stake to:\n\nzelcash-cli getnewaddress\n\nThe result will look similar to this \"1234567890H9sA5ArE5Y9rrrrgAfRtKLYUp\".  This will be your collateral storage and rewards payout address. This must be a transparent address (t-address).  Transfer your collateral for your desired tier of ZelNode to the address generated in Step 2. Ensure you send enough to cover any transaction fees and wait for at least 2 confirmations."
    [mn_outputs]="Once again in the CMD window on your PC paste\n\nzelcash-cli getzelnodeoutputs\n\nThis will output TxID and the output index, for example:\n{\n\"a9b31238d062ccb5f4b1eb6c3041d369cc014f5e6df38d2d303d791acd4302f2\": \"0\"\n}\nPaste just the first, long, number without any punctuation, here and the second number in the next screen."
    [mn_outputs_txin]="Enter the second, single digit number from the previous step (usually 0 or 1) here."
    [mn_conf]="On the control wallet machine open %AppData%\Roaming\ZelCash\zelnode.conf and paste the string that will appear on the next screen then save and close the file.\n\nIt should look like this\nZelNode1 168.104.100.190:16125 1234567890H9sA5ArE5Y9rrrrgAfRtKLYUp 13c385119f135c215a2bef7de37b534f1ac27f4d0f23c105d8ee431f9b797105 0"
    [wallet_conf]="On the control wallet PC, open %AppData%\Roaming\ZelCash\zelcash.conf in a text editor, and paste the lines that will appear on the next screen then save and close the file"
    [get_binaries]="Installing binaries to /usr/local/bin..."
    [vps_configs]="Creating configs in $wallet_location..."
    [vps_systemd]="Creating and installing the $project_name systemd service..."
    [start_mn]="Restart the control wallet.  In the CMD window paste the following command:\n\nzelcash-cli startzelnode alias false\n\nto start your Masternode.\n\nIt may take a while for your masternode to fully propagate"
)
# ------------------------------------------------------------------------------

# ==============================================================================
# INSTALL PACKAGES
# ==============================================================================
msgbox "${install_steps[install_dependencies]}"
wt_title="Installing dependencies..."
infobox "${install_steps[installing]}"
stfu install_packages
# ------------------------------------------------------------------------------

# ==============================================================================
# CONFIGURE SERVER
# ==============================================================================
wt_title="Server Config"
infobox "Configuring automatic security upgrades..."
stfu unattended-upgrades
# change_hostname
# stfu create_swap

iamroot

# harden_ssh #Needs work
infobox "Configuring firewall..."
stfu setup_ufw
infobox "Configuring Fail2Ban..."
stfu setup_fail2ban
# ------------------------------------------------------------------------------

# ==============================================================================
wt_title="Masternode Config"
# ==============================================================================
while [ -z $mn_priv_key ]; do
mn_priv_key=$(inputbox "${install_steps[create_nodekey]}")
done
while [ -z $mn_alias ]; do
mn_alias=$(inputbox "${install_steps[choose_alias]}")
    # note:  --default-item is not working here.  need fix.
done
msgbox "${install_steps[collateral_address]/"mn_alias"/"$mn_alias"}"
while [ -z $collateral_output_txid ]; do
collateral_output_txid=$(inputbox "${install_steps[mn_outputs]}")
done
while [ -z $collateral_output_index ]; do
collateral_output_index=$(inputbox "${install_steps[mn_outputs_txin]}")
done
msgbox "${install_steps[mn_conf]}"
    masternode_conf="$mn_alias $public_ip:$p2p_port $mn_priv_key $collateral_output_txid $collateral_output_index"
    text_to_copy $masternode_conf
msgbox "${install_steps[wallet_conf]}"
LOCAL_WALLET_CONF="rpc_user=${rpc_user}\nrpc_password=${rpc_password} password\nrpcallowip=127.0.0.1\nserver=1\ndaemon=1\ntxindex=1\nlogtimestamps=1\nmaxconnections=256"
    text_to_copy $LOCAL_WALLET_CONF
infobox "${install_steps[get_binaries]}"
    stfu download_binaries testnet
infobox "${install_steps[vps_configs]}"
server_wallet_conf="rpc_user=${rpc_user}\nrpc_password=${rpc_password}\nrpcallowip=127.0.0.1\nzelnode=1\nzelnodeprivkey=${mn_priv_key}\nlisten=1\nserver=1\ndaemon=1\ntxindex=1\nlogtimestamps=1\nmaxconnections=256\nexternalip=${public_ip}\nbind=${public_ip}:${p2p_port}\ndatadir=${wallet_location}"
    stfu wallet_configs
    stfu fetch_params
infobox "${install_steps[vps_systemd]}"
daemon_service="[Unit]\nDescription=$project_name daemon\nAfter=network.target\n\n[Service]\nExecStart=/usr/local/bin/$daemon_binary --daemon --shrinkdebugfile --conf=$wallet_location/$project_name.conf -pid=/run/$daemon_binary/$daemon_binary.pid\nRuntimeDirectory=$daemon_binary\nUser=$linux_user\nType=forking\nWorkingDirectory=$wallet_location\nPIDFile=/run/$daemon_binary/$daemon_binary.pid\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target"
    stfu daemon_service
#    stfu install_checkblocks
msgbox "${install_steps[start_mn]/"mn_alias"/"$mn_alias"}"

# ==============================================================================
# Display logo
# ==============================================================================
clear
echo -e "${project_logo}\n\nYour public ip address is ${public_ip}\nThe ${project_name}.conf and zelnode.conf are located at ${wallet_location}\nThe ${project_name} binaries are located in at /usr/local/bin\n\nUseful commands:\n'${project_cli} getzelnodestatus'   #Get the status of your masternode\n'${project_cli} --help'              #Get a list of things that ${project_cli} can do\n'sudo systemctl stop ${daemon_binary}'    #Stop the ${project_name} Daemon\n'sudo systemctl start ${daemon_binary}'   #Start the ${project_name} Daemon\n'sudo systemctl restart ${daemon_binary}' #Restart the ${project_name} Daemon\n'sudo systemctl status ${daemon_binary}'  #Get the status ${project_name} Daemon\n\nFor a beginners quick start for linux see https://steemit.com/tutorial/@greerso/linux-cli-command-line-interface-primer-for-beginners"\n\n
if [ "$linux_user" != "$USERNAME" ]; then
echo -e "The next time that you login to this server, you should use the username $USERNAME and password created in this script and disable root ssh login"
fi
su "$USERNAME"
cd ~
${project_cli} startzelnode local false
${project_cli} getzelnodestatus
#masternode_sync
# ------------------------------------------------------------------------------

# ==============================================================================
# TODO
# ==============================================================================
#	Validation on user input
#	Make Base Installs optional
#   Fail2Ban email reports of hacking activity
#   Harden SSH security
#       Change port 22
#       Disable root logon
#       Require ssh-keys
##Masternode install
#   Check for already installed
#       Check daemon up-to-date
#           install update
#	NTP and timezone
# ------------------------------------------------------------------------------
