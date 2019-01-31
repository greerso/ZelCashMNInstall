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
PROJECT_NAME="zelcash"
PROJECT_GITHUB_REPO="zelcash/zelcash"
GITHUB_BIN_SUFFIX=linux
declare -A NODE_REQ=(
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
RPC_PORT="17654"
P2P_PORT="17652"
#
export NEWT_COLORS=''
RPCUSER="${PROJECT_NAME}_$(head -c 8 /dev/urandom | base64)"
RPCPASSWORD="$(head -c 32 /dev/urandom | base64)"
LINUX_USER=$(who -m | awk '{print $1;}')
LINUX_USERPW="$(head -c 32 /dev/urandom | base64)"
PUBLIC_IP="$(dig +short myip.opendns.com @resolver1.opendns.com)"
INTERNALIP="$(hostname -I)"
HOSTNAME="$(cat /etc/hostname)"
SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
WALLET_LOCATION="${HOME}/.${PROJECT_NAME}"
DAEMON_BINARY="${PROJECT_NAME}d"
PROJECT_CLI="${PROJECT_NAME}-cli"
PROJECT_LOGO="                                      @@@                                      \                                  #@@@@@@@@@&                                  \                               @@@@@@@@,@@@@@@@@                               \                           #@@@@@@@*,,,,,,,(@@@@@@@.                           \                        @@@@@@@@,,,,,,,,,,,,,,,@@@@@@@@                        \                     @@@@@@@#,,,,,,,,,,,,,,,,,,,,,%@@@@@@@                     \                  @@@@@@@,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@@@@@@@                  \                  @@@@.,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.@@@@                  \                  @@@@....,,,,,,,,,,,,,,,,,,,,,,,,,,,....@@@@                  \               @@@@@@@@,......,,,,,,,,,,,,,,,,,,,....../@@@@@@@@               \            @@@@@@@@@@@@@@@......,,,,,,,,,,,,,......@@@@@@@@@@@@@@@            \        @@@@@@@@,@@@@@@@@@@@@@,......,,,,,......,@@@@@@@@@@@@@,@@@@@@@@        \     @@@@@@@@.......*@@@@@@@@@@@@@...........@@@@@@@@@@@@@#,,,,,,,@@@@@@@@     \ #@@@@@@@*..............@@@@@@@@@@@@.......@@@@@@@@@@@@,,,,,,,,,,,,,,,@@@@@@@& \@@@@@@.....................#@@@@@@@@.......@@@@@@@@#,,,,,,,,,,,,,,,,,,,,,@@@@@@\@@@,..........................@@@@@@.......@@@@@@.,,,,,,,,,,,,,,,,,,,,,,,,,%@@@\@@@,..........................@@@@@@.......@@@@@@.....,,,,,,,,,,,,,,,,,////%@@@\@@@,..........................@@@@@@.......@@@@@@........,,,,,,,,,,,///////%@@@\@@@,..........................@@@@@@.......@@@@@@............,,,///////////%@@@\@@@,..........................@@@@@@.......@@@@@@.............*////////////%@@@\@@@,..........................@@@@@@.......@@@@@@.............*////////////%@@@\@@@,..........................@@@@@@.......@@@@@@.............*////////////%@@@\@@@,..........................@@@@@@@@@@@@@@@@@@@.............*////////////%@@@\@@@@@@.....................#@@@@@@ @@@@@@@@@ @@@@@@(..........*//////////@@@@@@\ @@@@@@@@,..............@@@@@@@@       @       @@@@@@@@.......*///////@@@@@@@@ \     @@@@@@@@.......,@@@@@@@@                      @@@@@@@/...*///@@@@@@@@     \        @@@@@@@@.@@@@@@@@                             @@@@@@@@*@@@@@@@@        \            @@@@@@@@@@                                   @@@@@@@@@@ "
WT_BACKTITLE="$PROJECT_NAME Masternode Installer"
WT_TITLE="Installing the $PROJECT_NAME Masternode..."
declare MN_ALIAS
declare MN_PRIV_KEY
declare COLLATERAL_OUTPUT_TXID
declare COLLATERAL_OUTPUT_INDEX
declare -a BASE_PKGS=(\
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
declare -a PROJECT_PKGS=(\
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

# infobox TEXT
infobox() {
    BASE_LINES=10
    WT_HEIGHT=$(echo -e "$@" | wc -l)
    (( WT_HEIGHT=WT_HEIGHT+BASE_LINES ))
    WT_WIDTH=78
    WT_SIZE="$WT_HEIGHT $WT_WIDTH"
    TERM=ansi whiptail \
    --infobox "$@" \
    --backtitle "$WT_BACKTITLE" \
    --title "$WT_TITLE" \
    $WT_SIZE
}

# msgbox TEXT
msgbox() {
    BASE_LINES=10
    WT_HEIGHT=$(echo -e "$@" | wc -l)
    (( WT_HEIGHT=WT_HEIGHT+BASE_LINES ))
    WT_WIDTH=78
    WT_SIZE="$WT_HEIGHT $WT_WIDTH"
    TERM=ansi whiptail \
    --msgbox "$@" \
    --backtitle "$WT_BACKTITLE" \
    --title "$WT_TITLE" \
    $WT_SIZE
}

# inputbox TEXT
inputbox() {
    BASE_LINES=10
    WT_HEIGHT=$(echo -e "$@" | wc -l)
    (( WT_HEIGHT=WT_HEIGHT+BASE_LINES ))
    WT_WIDTH=78
    WT_SIZE="$WT_HEIGHT $WT_WIDTH"
    TERM=ansi whiptail \
    --inputbox "$@" \
    --backtitle "$WT_BACKTITLE" \
    --title "$WT_TITLE" \
    3>&1 1>&2 2>&3 \
    $WT_SIZE
}

# yesnobox TEXT
yesnobox() {
BASE_LINES=8
WT_HEIGHT=$(echo -e "$@" | wc -l)
(( WT_HEIGHT=WT_HEIGHT+BASE_LINES ))
WT_WIDTH=78
WT_SIZE="$WT_HEIGHT $WT_WIDTH"
TERM=ansi whiptail \
--yesno "$@" \
--backtitle "$WT_BACKTITLE" \
--title "$WT_TITLE" \
3>&1 1>&2 2>&3 \
$WT_SIZE
}

min_ubuntu() {
    UBUNTU_VER=$(lsb_release -rs)
    if [[ $UBUNTU_VER < 16.04 ]]; then
    msgbox "At least Ubuntu 16.04 is required, you have $UBUNTU_VER.  Exiting..."
    exit 1
    fi
}

auth_sudo() {
    if [ "$(id -nu)" != "root" ]; then
    sudo -k
    PASSWORD=$(whiptail --backtitle "$PROJECT_NAME Masternode Installer" --title "Authentication required" --passwordbox "Installing $PROJECT_NAME requires root privilege. Please authenticate to begin the installation.\n\n[sudo] Password for user $USER:" 12 50 3>&2 2>&1 1>&3-)
    exec sudo -E -S -p '' "$0" "$@" <<< "$PASSWORD"
    fi
}

daemon_running() {
    if [ -n "$(pidof $DAEMON_BINARY)" ]; then
    msgbox "The $PROJECT_NAME daemon is already running."
    # what user is running the daemon
    # where is the wallet stored
    # is systemd controlling the daemon or was it started from a cron job?
    # check for updates
    exit 1
    fi
}

enable_sshkeys() {
# did user login using sshkeys?
# is user root user?
# does user want to use this account to run daemon
}

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
aptitude -yq3 install ${BASE_PKGS[@]} $@
aptitude -yq3 install ${PROJECT_PKGS[@]}

# Add bitcoin repo for ancient version of libdb if wallet requires.
# stfu add-apt-repository -y ppa:bitcoin/bitcoin
# stfu apt update
# stfu aptitude -yq3 install \
#   libdb4.8-dev \
#   libdb4.8++-dev
}

change_hostname() {
HOSTNAME=$(hostname)
if [ -z "$1" ]; then
newHostname=$(inputbox "Your hostname is $HOSTNAME,  please enter a new hostname then press ok.")
else
newHostname="$1"
fi
sed -i "s|$Hostname|$newHostname|1" /etc/hostname
if grep -q "$Hostname" /etc/hosts; then
sed -i "s|$Hostname|$newHostname|1" /etc/hosts
else
echo "127.0.0.1 $newHostname" >> /etc/hosts
fi
}

create_swap() {
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
TOTAL_SWP=$(free -m | awk '/^Swap:/{print $2}')
TOTAL_M=$(($TOTAL_MEM + $TOTAL_SWP))
if [ $TOTAL_M -lt 4000 ]; then
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
USER_PASSWORD=$(inputbox "Please enter a password for '${USERNAME}'")
adduser --gecos "" --disabled-password --quiet "$USERNAME"
echo "$USERNAME:$USER_PASSWORD" | chpasswd
# Add user to sudoers
usermod -a -G sudo "$USERNAME"
LINUX_USER=$USERNAME
WALLET_LOCATION="$(eval echo "~$USERNAME")/.${PROJECT_NAME}"
# add option to ask instead of adding to sudoers by default
# add a loop to add more users  
}

iamroot() {
	if [ "$LINUX_USER" == "root" ]; then
	WT_TITLE="I AM ROOT" 
	if (yesnobox "You logged into your server as root.\n\nIt is not reccomended to install and run your masternode as root. Would you like to create a normal user?"); then
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
SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
if [ $SSH_PORT -eq 22 ] ; then
NEW_SSH_PORT=$(inputbox "SSH is currently running on $NEW_SSH_PORT.  Botnets scan are constantly scanning this port.  Enter a new port or press enter to accept port 2222" )
fi
if grep -q Port /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})Port)( *)?(.*)|Port $NEW_SSH_PORT|1" /etc/ssh/sshd_config
else
echo "Port $NEW_SSH_PORT" >> /etc/ssh/sshd_config
fi
# Disable root user ssh login
# Make sure that you have a normal user before doing this
if grep -q PermitRootLogin /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})PermitRootLogin)( *)?(.*)|PermitRootLogin no|1" /etc/ssh/sshd_config
else
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi
# Disable the use of passwords with ssh
# Add ssh-key for remote user to LINUX_USER .ssh/allowed_keys
if grep -q PasswordAuthentication /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})PasswordAuthentication)( *)?(.*)|PasswordAuthentication no|1" /etc/ssh/sshd_config
else
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
fi
# Restart the ssh daemon
systemctl restart sshd
}

setup_ufw() {
    SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
    ALLOWED_PORTS=[$@]
    REMOTE_IP=$(echo -e $SSH_CLIENT | awk '{ print $1}')
    
    if ! [ -f /etc/ufw/ufw.conf ]; then
        apt-get -y install ufw
    fi
    
    # Open all outgoing ports, block all incoming ports then open port $SSH_PORT for ssh.
    ufw default allow outgoing
    ufw default deny incoming
    
    # Open ports
    ufw limit $SSH_PORT/tcp comment 'ssh port'
    ufw allow $P2P_PORT/tcp comment 'mn p2p port'
    ufw allow $RPC_PORT/tcp comment 'mn rpc port'
    allow all ports from $REMOTE_IP
    # Enable the firewall
    ufw --force enable
}

setup_fail2ban() {
REMOTE_IP=$(echo -e $SSH_CLIENT | awk '{ print $1}')
FQDN="$(hostname -f)"
SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
JAIL_LOCAL="[blacklist]\nenabled = true\nlogpath  = /var/log/fail2ban.*\nbanaction = blacklist\nbantime  = 31536000   \; 1 year\nfindtime = 31536000   \; 1 year\nmaxretry = 10\n\n[Definition]\nloglevel = INFO\nlogtarget = /var/log/fail2ban.log\nsyslogsocket = auto\nsocket = /var/run/fail2ban/fail2ban.sock\npidfile = /var/run/fail2ban/fail2ban.pid\ndbfile = /var/lib/fail2ban/fail2ban.sqlite3\ndbpurgeage = 86400"
JAIL_LOCAL=$(echo -e $JAIL_LOCAL)

if [ ! -f /etc/fail2ban/jail.local ]; then
apt -y install fail2ban
cat <<EOF > /etc/fail2ban/jail.local
$JAIL_LOCAL
EOF
fi

sed -i -e 's|ignoreip = 127.0.0.1/8|ignoreip = $REMOTE_IP|g' /etc/fail2ban/jail.local
# jail.local:
# [sshd]
# action = %(action_)s
# smtp.py[host="host:25", user="my-account", password="my-pwd", sender="sender@example.com", dest="example@example.com", name="%(__name__)s"]
# sed -i -e 's|destemail = root@localhost|destemail = me@myemail.com |g' /etc/fail2ban/jail.local
# sed -i -e 's|sender = root@localhost|sender = fail2ban@$FQDN\nsendername = Fail2Ban|g' /etc/fail2ban/jail.local
# sed -i -e 's|mta = sendmail|mta = mail|g' /etc/fail2ban/jail.local
sed -i -e 's|action = %(action_)s|action = %(action_mwl)s|g' /etc/fail2ban/jail.local
sed -i -e 's|= ssh|= $SSH_PORT|g' /etc/fail2ban/jail.local

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

# download_binaries PROJECT_NAME PROJECT_GITHUB_REPO
download_binaries() {
GITHUB_BIN_URL="$(curl -sSL https://api.github.com/repos/${PROJECT_GITHUB_REPO}/releases/latest | jq -r ".assets[] | select(.name | test(\"$GITHUB_BIN_SUFFIX\")) | .browser_download_url")"    
    curl -sSL "$GITHUB_BIN_URL" | tar xvz -C /usr/local/bin/
}

wallet_configs() {
mkdir -p $WALLET_LOCATION
cat <<EOF > $WALLET_LOCATION/zelnode.conf
$MASTERNODE_CONF
EOF
SERVER_WALLET_CONF=$(echo -e $SERVER_WALLET_CONF)
cat <<EOF > $WALLET_LOCATION/${PROJECT_NAME}.conf
$SERVER_WALLET_CONF
EOF
chown -R $LINUX_USER $WALLET_LOCATION
}

daemon_service() {
DAEMON_SERVICE=$(echo -e $DAEMON_SERVICE)
cat <<EOF > /etc/systemd/system/$DAEMON_BINARY.service
$DAEMON_SERVICE
EOF
chmod 755 /etc/systemd/system/$DAEMON_BINARY.service
systemctl daemon-reload
systemctl enable $DAEMON_BINARY
systemctl restart $DAEMON_BINARY
}

masternode_sync() {
echo "Syncing Masternode..."
until ${DAEMON_BINARY} masternode debug | grep -m 1 "Masternode successfully started"; do
echo "."
sleep 3
done
}

install_checkblocks() {
CHECK_BLOCKS="previousBlock=$(cat WALLET_LOCATION/blockcount)\ncurrentBlock=$(${PROJECT_CLI} getblockcount)\n\n${PROJECT_CLI} getblockcount > WALLET_LOCATION/blockcount\n\nif [ "$previousBlock" == "$currentBlock" ]; then\n\nsudo systemctl restart ${DAEMON_BINARY}\n\nfi"
CHECK_BLOCKS=$(echo -e $CHECK_BLOCKS)
echo "%sudo ALL=NOPASSWD: /bin/systemctl restart ${DAEMON_BINARY}.service" >> /etc/sudoers
CB_CRON="*/30 * * * * ${LINUX_USER} sudo ${WALLET_LOCATION}/checkdaemon.sh >> ${WALLET_LOCATION}/cron.log"
cat <<EOF > $WALLET_LOCATION/checkblocks.sh
$CHECKBLOCKS
EOF
cat <<EOF > /etc/cron.d/${PROJECT_NAME}-checkdaemon
$CB_CRON
EOF
chown -R ${LINUX_USER}:${LINUX_USER} $WALLET_LOCATION
chmod +x ${WALLET_LOCATION}/checkblocks.sh
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
declare -a INSTALL_OPTIONS=("
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
declare -A INSTALL_STEPS=(
    [installing]="Installing packages required for setup...\n(this could take a few minutes)"
    [install_dependencies]="This script will walk you through the following:\n\n${INSTALL_OPTIONS}\n\nYou will need:\n- A Swing wallet with at least "${NODE_REQ[basic_stake]}" coins and to know how to copy/paste."
    [create_nodekey]="Launch the control wallet (wallet on your everyday PC, not on this VPS).\nOpen CMD.\nChange directory to the directory containing zelcash-cli.\nPaste the command\n\nzelcash-cli createzelnodekey\n\n. This will be the private key for the ZelNode, *not* your collateral/rewards Private Key."
    [choose_alias]="Choose an alias for your masternode, for example MN1, then enter it here"
    [collateral_address]="Back in the CMD window on your PC paste the following command to get a public address to send the stake to:\n\nzelcash-cli getnewaddress\n\nThe result will look similar to this \"1234567890H9sA5ArE5Y9rrrrgAfRtKLYUp\".  This will be your collateral storage and rewards payout address. This must be a transparent address (t-address).  Transfer your collateral for your desired tier of ZelNode to the address generated in Step 2. Ensure you send enough to cover any transaction fees and wait for at least 2 confirmations."
    [mn_outputs]="Once again in the CMD window on your PC paste\n\nzelcash-cli getzelnodeoutputs\n\nThis will output TxID and the output index, for example:\n{\n\"a9b31238d062ccb5f4b1eb6c3041d369cc014f5e6df38d2d303d791acd4302f2\": \"0\"\n}\nPaste just the first, long, number without any punctuation, here and the second number in the next screen."
    [mn_outputs_txin]="Enter the second, single digit number from the previous step (usually 0 or 1) here."
    [mn_conf]="On the control wallet machine open %AppData%\Roaming\ZelCash\zelnode.conf and paste the string that will appear on the next screen then save and close the file.\n\nIt should look like this\nZelNode1 168.104.100.190:16125 1234567890H9sA5ArE5Y9rrrrgAfRtKLYUp 13c385119f135c215a2bef7de37b534f1ac27f4d0f23c105d8ee431f9b797105 0"
    [wallet_conf]="On the control wallet PC, open %AppData%\Roaming\ZelCash\zelcash.conf in a text editor, and paste the lines that will appear on the next screen then save and close the file"
    [get_binaries]="Installing binaries to /usr/local/bin..."
    [vps_configs]="Creating configs in $WALLET_LOCATION..."
    [vps_systemd]="Creating and installing the $PROJECT_NAME systemd service..."
    [start_mn]="Restart the control wallet.  In the CMD window paste the following command:\n\nzelcash-cli startzelnode alias false\n\nto start your Masternode.\n\nIt may take a while for your masternode to fully propagate"
)
# ------------------------------------------------------------------------------

# ==============================================================================
# INSTALL PACKAGES
# ==============================================================================
msgbox "${INSTALL_STEPS[install_dependencies]}"
WT_TITLE="Installing dependencies..."
infobox "${INSTALL_STEPS[installing]}"
stfu install_packages
# ------------------------------------------------------------------------------

# ==============================================================================
# CONFIGURE SERVER
# ==============================================================================
WT_TITLE="Server Config"
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
WT_TITLE="Masternode Config"
# ==============================================================================
while [ -z $MN_PRIV_KEY ]; do
MN_PRIV_KEY=$(inputbox "${INSTALL_STEPS[create_nodekey]}")
done
while [ -z $MN_ALIAS ]; do
MN_ALIAS=$(inputbox "${INSTALL_STEPS[choose_alias]}")
    # note:  --default-item is not working here.  need fix.
done
msgbox "${INSTALL_STEPS[collateral_address]/"MN_ALIAS"/"$MN_ALIAS"}"
while [ -z $COLLATERAL_OUTPUT_TXID ]; do
COLLATERAL_OUTPUT_TXID=$(inputbox "${INSTALL_STEPS[mn_outputs]}")
done
while [ -z $COLLATERAL_OUTPUT_INDEX ]; do
COLLATERAL_OUTPUT_INDEX=$(inputbox "${INSTALL_STEPS[mn_outputs_txin]}")
done
msgbox "${INSTALL_STEPS[mn_conf]}"
    MASTERNODE_CONF="$MN_ALIAS $PUBLIC_IP:$P2P_PORT $MN_PRIV_KEY $COLLATERAL_OUTPUT_TXID $COLLATERAL_OUTPUT_INDEX"
    text_to_copy $MASTERNODE_CONF
msgbox "${INSTALL_STEPS[wallet_conf]}"
LOCAL_WALLET_CONF="rpcuser=${RPCUSER}\nrpcpassword=${RPCPASSWORD} password\nrpcallowip=127.0.0.1\nserver=1\ndaemon=1\ntxindex=1\nlogtimestamps=1\nmaxconnections=256"
    text_to_copy $LOCAL_WALLET_CONF
infobox "${INSTALL_STEPS[get_binaries]}"
    stfu download_binaries
infobox "${INSTALL_STEPS[vps_configs]}"
SERVER_WALLET_CONF="rpcuser=${RPCUSER}\nrpcpassword=${RPCPASSWORD}\nrpcallowip=127.0.0.1\nzelnode=1\nzelnodeprivkey=${MN_PRIV_KEY}\nlisten=1\nserver=1\ndaemon=1\ntxindex=1\nlogtimestamps=1\nmaxconnections=256\nexternalip=${PUBLIC_IP}\nbind=${PUBLIC_IP}:${P2P_PORT}\ndatadir=${WALLET_LOCATION}"
    stfu wallet_configs
infobox "${INSTALL_STEPS[vps_systemd]}"
DAEMON_SERVICE="[Unit]\nDescription=$PROJECT_NAME daemon\nAfter=network.target\n\n[Service]\nExecStart=/usr/local/bin/$DAEMON_BINARY --daemon --shrinkdebugfile --conf=$WALLET_LOCATION/$PROJECT_NAME.conf -pid=/run/$DAEMON_BINARY/$DAEMON_BINARY.pid\nRuntimeDirectory=$DAEMON_BINARY\nUser=$LINUX_USER\nType=forking\nWorkingDirectory=$WALLET_LOCATION\nPIDFile=/run/$DAEMON_BINARY/$DAEMON_BINARY.pid\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target"
    stfu daemon_service
#    stfu install_checkblocks
msgbox "${INSTALL_STEPS[start_alias]/"MN_ALIAS"/"$MN_ALIAS"}"
# ==============================================================================
# Display logo
# ==============================================================================
clear
echo -e "${PROJECT_LOGO}\n\nYour public ip address is ${PUBLIC_IP}\nThe ${PROJECT_NAME}.conf and zelnode.conf are located at ${WALLET_LOCATION}\nThe ${PROJECT_NAME} binaries are located in at /usr/local/bin\n\nUseful commands:\n'${PROJECT_CLI} masternode status'   #Get the status of your masternode\n'${PROJECT_CLI} --help'              #Get a list of things that ${PROJECT_CLI} can do\n'sudo systemctl stop ${DAEMON_BINARY}'    #Stop the ${PROJECT_NAME} Daemon\n'sudo systemctl start ${DAEMON_BINARY}'   #Start the ${PROJECT_NAME} Daemon\n'sudo systemctl restart ${DAEMON_BINARY}' #Restart the ${PROJECT_NAME} Daemon\n'sudo systemctl status ${DAEMON_BINARY}'  #Get the status ${PROJECT_NAME} Daemon\n\nFor a beginners quick start for linux see https://steemit.com/tutorial/@greerso/linux-cli-command-line-interface-primer-for-beginners"\n\n
if [ "$LINUX_USER" != "$USERNAME" ]; then
echo -e "The next time that you login to this server, you should use the username $USERNAME and password created in this script and disable root ssh login"
fi
su "$USERNAME"
cd ~
${PROJECT_CLI} startzelnode local false
${PROJECT_CLI} getzelnodestatus
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
