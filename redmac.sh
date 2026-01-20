#!/usr/bin/env bash

if [ -t 1 ]; then
  RED="$(printf '\033[31m')"
  GREEN="$(printf '\033[32m')"
  YELLOW="$(printf '\033[33m')"
  BLUE="$(printf '\033[34m')"
  BOLD="$(printf '\033[1m')"
  RESET="$(printf '\033[0m')"
else
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  BOLD=""
  RESET=""
fi

info() {
  printf "%b[*]%b %s\n" "$BLUE" "$RESET" "$1"
}

success() {
  printf "%b[+]%b %s\n" "$GREEN" "$RESET" "$1"
}

error() {
  printf "%b[-]%b %s\n" "$RED" "$RESET" "$1"
}

warn() {
  printf "%b[!]%b %s\n" "$YELLOW" "$RESET" "$1"
}


 

print_banner() {
  echo
  echo "${RED}    ____          _                  ${RESET}"
  echo "${RED}   |  _ \ ___  __| |_ __ ___   __ _  ___ ${RESET}"
  echo "${RED}   | |_) / _ \/ _\` | '_ \` _ \ / _\` |/ __|${RESET}"
  echo "${RED}   |  _ <  __/ (_| | | | | | | (_| | (__ ${RESET}"
  echo "${RED}   |_| \_\___|\__,_|_| |_| |_|\__,_|\___|${RESET}"
  echo
  echo "${RED}   Red Team Tools Installer for macOS${RESET}"
  echo
}

print_banner

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew not found, installing..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [ -x "/opt/homebrew/bin/brew" ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [ -x "/usr/local/bin/brew" ]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
else
  echo "Homebrew found"
fi

brew update || true

BREW_FORMULAE=(
  nmap
  masscan
  hydra
  hashcat
  john
  aircrack-ng
  gobuster
  sqlmap
  nikto
  theharvester
  amass
  ffuf
  rustscan
  proxychains-ng
  tor
  nuclei
  subfinder
  httpx
  naabu
  exploitdb
  feroxbuster
  binwalk
  socat
  sslscan
  wget
  cmake
  openssl@3
  tmux
  jq
  radare2
  apktool
)
BREW_CASKS=(
  wireshark
  metasploit
  mitmproxy
  owasp-zap
  postman
)

PIP3_PACKAGES=(
  dirsearch
  wafw00f
  arjun
  impacket
  hashid
  frida-tools
  objection
)
PYTOOLS_VENV="$HOME/.pentest-python-tools-venv"
if command -v brew >/dev/null 2>&1; then
  BIN_DIR="$(brew --prefix)/bin"
else

  if [ -d "/opt/homebrew/bin" ]; then
    BIN_DIR="/opt/homebrew/bin"
  else
    BIN_DIR="/usr/local/bin"
  fi
fi
LOG_FILE="$HOME/.redmac-install.log"
INSTALLED_TOOLS=()
FAILED_TOOLS=()

install_brew_formula() {
  local pkg="$1"
  if brew list --formula "$pkg" >/dev/null 2>>"$LOG_FILE"; then
    return
  else
    info "Installing brew formula: $pkg..."
    if brew install "$pkg" >/dev/null 2>>"$LOG_FILE"; then
      success "Installed $pkg"
      INSTALLED_TOOLS+=("$pkg")
    else
      error "Failed to install $pkg"
      FAILED_TOOLS+=("$pkg")
    fi
  fi
}

install_brew_cask() {
  local pkg="$1"
  if brew list --cask "$pkg" >/dev/null 2>>"$LOG_FILE"; then
    return
  else
    info "Installing brew cask: $pkg..."
    if brew install --cask "$pkg" >/dev/null 2>>"$LOG_FILE"; then
      success "Installed $pkg"
      INSTALLED_TOOLS+=("$pkg")
    else
      error "Failed to install $pkg"
      FAILED_TOOLS+=("$pkg")
    fi
  fi
}

install_pip3_package() {
  local pkg="$1"
  if ! command -v python3 >/dev/null 2>&1; then
    info "Python3 not found. Installing python..."
    if ! brew install python >/dev/null 2>>"$LOG_FILE"; then
      error "Failed to install python"
      FAILED_TOOLS+=("$pkg")
      return
    fi
  fi
  if [ ! -d "$PYTOOLS_VENV" ]; then
    info "Creating Python virtual environment..."
    if ! python3 -m venv "$PYTOOLS_VENV" >/dev/null 2>>"$LOG_FILE"; then
      error "Failed to create virtual environment"
      FAILED_TOOLS+=("$pkg")
      return
    fi
  fi
  if "$PYTOOLS_VENV/bin/python" -m pip show "$pkg" >/dev/null 2>>"$LOG_FILE"; then
    return
  else
    info "Installing pip package: $pkg..."
    if "$PYTOOLS_VENV/bin/python" -m pip install "$pkg" >/dev/null 2>>"$LOG_FILE"; then
      success "Installed $pkg"
      INSTALLED_TOOLS+=("$pkg")
    else
      error "Failed to install $pkg"
      FAILED_TOOLS+=("$pkg")
    fi
  fi
  

  for bin_file in "$PYTOOLS_VENV/bin"/*; do
    local base_name
    base_name=$(basename "$bin_file")
    if [[ "$base_name" != "python"* && "$base_name" != "pip"* && "$base_name" != "activate"* && "$base_name" != "easy_install"* ]]; then
      ln -sf "$bin_file" "$BIN_DIR/$base_name"
    fi
  done


  if [ -f "$BIN_DIR/nxc" ]; then
    ln -sf "$BIN_DIR/nxc" "$BIN_DIR/cme"
    ln -sf "$BIN_DIR/nxc" "$BIN_DIR/crackmapexec"
    echo "Created cme/crackmapexec aliases pointing to nxc" >> "$LOG_FILE"
  fi
}

install_payloads() {

  if [ ! -f "$BIN_DIR/chisel_server" ]; then
    info "Installing chisel_server..."
    if wget -q "https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_darwin_amd64.gz" -O "$BIN_DIR/chisel_osx.gz" 2>>"$LOG_FILE"; then
      gunzip -c "$BIN_DIR/chisel_osx.gz" > "$BIN_DIR/chisel_server"
      rm "$BIN_DIR/chisel_osx.gz"
      chmod +x "$BIN_DIR/chisel_server"
      success "Installed chisel_server"
      INSTALLED_TOOLS+=("chisel_server")
    else
      error "Failed to install chisel_server"
      FAILED_TOOLS+=("chisel_server")
    fi
  fi

  if [ ! -f "$BIN_DIR/chisel_linux_64" ]; then
    info "Installing chisel_linux_64..."
    if wget -q "https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz" -O "$BIN_DIR/chisel_linux_64.gz" 2>>"$LOG_FILE"; then
      gunzip -c "$BIN_DIR/chisel_linux_64.gz" > "$BIN_DIR/chisel_linux_64"
      rm "$BIN_DIR/chisel_linux_64.gz"
      success "Installed chisel_linux_64"
      INSTALLED_TOOLS+=("chisel_linux_64")
    else
      error "Failed to install chisel_linux_64"
      FAILED_TOOLS+=("chisel_linux_64")
    fi
  fi

  if [ ! -f "$BIN_DIR/chisel_linux_386" ]; then
    info "Installing chisel_linux_386..."
    if wget -q "https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_386.gz" -O "$BIN_DIR/chisel_linux_386.gz" 2>>"$LOG_FILE"; then
      gunzip -c "$BIN_DIR/chisel_linux_386.gz" > "$BIN_DIR/chisel_linux_386"
      rm "$BIN_DIR/chisel_linux_386.gz"
      success "Installed chisel_linux_386"
      INSTALLED_TOOLS+=("chisel_linux_386")
    else
      error "Failed to install chisel_linux_386"
      FAILED_TOOLS+=("chisel_linux_386")
    fi
  fi


  if [ ! -f "$BIN_DIR/linpeas.sh" ]; then
    info "Installing linpeas..."
    if wget -q "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" -O "$BIN_DIR/linpeas.sh" 2>>"$LOG_FILE"; then
      success "Installed linpeas"
      INSTALLED_TOOLS+=("linpeas")
    else
      error "Failed to install linpeas"
      FAILED_TOOLS+=("linpeas")
    fi
  fi

  if [ ! -f "$BIN_DIR/winpeas.bat" ]; then
    info "Installing winpeas.bat..."
    if wget -q "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat" -O "$BIN_DIR/winpeas.bat" 2>>"$LOG_FILE"; then
      success "Installed winpeas.bat"
      INSTALLED_TOOLS+=("winpeas.bat")
    else
      error "Failed to install winpeas.bat"
      FAILED_TOOLS+=("winpeas.bat")
    fi
  fi

  if [ ! -f "$BIN_DIR/winpeas.exe" ]; then
    info "Installing winpeas.exe..."
    if wget -q "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe" -O "$BIN_DIR/winpeas.exe" 2>>"$LOG_FILE"; then
      success "Installed winpeas.exe"
      INSTALLED_TOOLS+=("winpeas.exe")
    else
      error "Failed to install winpeas.exe"
      FAILED_TOOLS+=("winpeas.exe")
    fi
  fi


  if [ ! -f "$BIN_DIR/linenum.sh" ]; then
    info "Installing linenum..."
    if wget -q "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" -O "$BIN_DIR/linenum.sh" 2>>"$LOG_FILE"; then
      success "Installed linenum"
      INSTALLED_TOOLS+=("linenum")
    else
      error "Failed to install linenum"
      FAILED_TOOLS+=("linenum")
    fi
  fi


  if [ ! -f "$BIN_DIR/linux-exploit-suggester.sh" ]; then
    info "Installing linux-exploit-suggester..."
    if wget -q "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" -O "$BIN_DIR/linux-exploit-suggester.sh" 2>>"$LOG_FILE"; then
      success "Installed linux-exploit-suggester"
      INSTALLED_TOOLS+=("linux-exploit-suggester")
    else
      error "Failed to install linux-exploit-suggester"
      FAILED_TOOLS+=("linux-exploit-suggester")
    fi
  fi


  if [ ! -f "$BIN_DIR/lse.sh" ]; then
    info "Installing lse..."
    if wget -q "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O "$BIN_DIR/lse.sh" 2>>"$LOG_FILE"; then
      success "Installed lse"
      INSTALLED_TOOLS+=("lse")
    else
      error "Failed to install lse"
      FAILED_TOOLS+=("lse")
    fi
  fi


  if [ ! -f "$BIN_DIR/pspy64" ]; then
    info "Installing pspy64..."
    if wget -q "https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64" -O "$BIN_DIR/pspy64" 2>>"$LOG_FILE"; then
      success "Installed pspy64"
      INSTALLED_TOOLS+=("pspy64")
    else
      error "Failed to install pspy64"
      FAILED_TOOLS+=("pspy64")
    fi
  fi
  if [ ! -f "$BIN_DIR/pspy32" ]; then
    info "Installing pspy32..."
    if wget -q "https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32" -O "$BIN_DIR/pspy32" 2>>"$LOG_FILE"; then
      success "Installed pspy32"
      INSTALLED_TOOLS+=("pspy32")
    else
      error "Failed to install pspy32"
      FAILED_TOOLS+=("pspy32")
    fi
  fi


  if [ ! -f "$BIN_DIR/powerup.ps1" ]; then
    info "Installing powerup..."
    if wget -q "https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1" -O "$BIN_DIR/powerup.ps1" 2>>"$LOG_FILE"; then
      success "Installed powerup"
      INSTALLED_TOOLS+=("powerup")
    else
      error "Failed to install powerup"
      FAILED_TOOLS+=("powerup")
    fi
  fi


  if [ ! -f "$BIN_DIR/jaws-enum.ps1" ]; then
    info "Installing jaws..."
    if wget -q "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1" -O "$BIN_DIR/jaws-enum.ps1" 2>>"$LOG_FILE"; then
      success "Installed jaws"
      INSTALLED_TOOLS+=("jaws")
    else
      error "Failed to install jaws"
      FAILED_TOOLS+=("jaws")
    fi
  fi


  if [ ! -f "$BIN_DIR/printspoof.exe" ]; then
    info "Installing printspoofer..."
    if wget -q "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe" -O "$BIN_DIR/printspoof.exe" 2>>"$LOG_FILE"; then
      success "Installed printspoofer"
      INSTALLED_TOOLS+=("printspoofer")
    else
      error "Failed to install printspoofer"
      FAILED_TOOLS+=("printspoofer")
    fi
  fi


  if [ ! -f "$BIN_DIR/invoke-powershelltcp.ps1" ]; then
    info "Installing nishang-rev..."
    if wget -q "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1" -O "$BIN_DIR/invoke-powershelltcp.ps1" 2>>"$LOG_FILE"; then
      success "Installed nishang-rev"
      INSTALLED_TOOLS+=("nishang-rev")
    else
      error "Failed to install nishang-rev"
      FAILED_TOOLS+=("nishang-rev")
    fi
  fi

  if [ ! -f "$BIN_DIR/php-rev-shell.php" ]; then
    info "Installing php-rev-shell..."
    if wget -q "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" -O "$BIN_DIR/php-rev-shell.php" 2>>"$LOG_FILE"; then
      success "Installed php-rev-shell"
      INSTALLED_TOOLS+=("php-rev-shell")
    else
      error "Failed to install php-rev-shell"
      FAILED_TOOLS+=("php-rev-shell")
    fi
  fi


  if [ ! -f "$BIN_DIR/RsaToHmac.py" ]; then
    info "Installing RsaToHmac.py..."
    if wget -q "https://raw.githubusercontent.com/cyberblackhole/TokenBreaker/master/RsaToHmac.py" -O "$BIN_DIR/RsaToHmac.py" 2>>"$LOG_FILE"; then
      chmod +x "$BIN_DIR/RsaToHmac.py"
      success "Installed RsaToHmac.py"
      INSTALLED_TOOLS+=("RsaToHmac.py")
    else
      error "Failed to install RsaToHmac.py"
      FAILED_TOOLS+=("RsaToHmac.py")
    fi
  fi
  if [ ! -f "$BIN_DIR/TheNone.py" ]; then
    info "Installing TheNone.py..."
    if wget -q "https://raw.githubusercontent.com/cyberblackhole/TokenBreaker/master/TheNone.py" -O "$BIN_DIR/TheNone.py" 2>>"$LOG_FILE"; then
      chmod +x "$BIN_DIR/TheNone.py"
      success "Installed TheNone.py"
      INSTALLED_TOOLS+=("TheNone.py")
    else
      error "Failed to install TheNone.py"
      FAILED_TOOLS+=("TheNone.py")
    fi
  fi

  "$PYTOOLS_VENV/bin/python" -m pip install -r "https://raw.githubusercontent.com/cyberblackhole/TokenBreaker/master/requirements.txt" >/dev/null 2>>"$LOG_FILE" || true


   if [ ! -s "$BIN_DIR/jwt-cracker" ]; then
     info "Installing jwt-cracker..."

     BUILD_DIR=$(mktemp -d)
     if wget -q "https://raw.githubusercontent.com/brendan-rius/c-jwt-cracker/master/Makefile" -O "$BUILD_DIR/Makefile" && \
        wget -q "https://raw.githubusercontent.com/brendan-rius/c-jwt-cracker/master/base64.c" -O "$BUILD_DIR/base64.c" && \
        wget -q "https://raw.githubusercontent.com/brendan-rius/c-jwt-cracker/master/base64.h" -O "$BUILD_DIR/base64.h" && \
        wget -q "https://raw.githubusercontent.com/brendan-rius/c-jwt-cracker/master/main.c" -O "$BUILD_DIR/main.c"; then
       

       if [ -d "/opt/homebrew/opt/openssl@3" ]; then
         OPENSSL_PATH="/opt/homebrew/opt/openssl@3"
       elif [ -d "/usr/local/opt/openssl@3" ]; then
         OPENSSL_PATH="/usr/local/opt/openssl@3"
       else
         OPENSSL_PATH=""
       fi
 
       if [ -n "$OPENSSL_PATH" ]; then
         if make -C "$BUILD_DIR" OPENSSL="$OPENSSL_PATH/include" OPENSSL_LIB="-L$OPENSSL_PATH/lib" >/dev/null 2>>"$LOG_FILE"; then

           cat "$BUILD_DIR/jwtcrack" > "$BIN_DIR/jwt-cracker"
           chmod +x "$BIN_DIR/jwt-cracker"
           success "Installed jwt-cracker"
           INSTALLED_TOOLS+=("jwt-cracker")
         else
           error "Failed to install jwt-cracker (make failed)"
           FAILED_TOOLS+=("jwt-cracker")
         fi
       else

          if make -C "$BUILD_DIR" >/dev/null 2>>"$LOG_FILE"; then
             cat "$BUILD_DIR/jwtcrack" > "$BIN_DIR/jwt-cracker"
             chmod +x "$BIN_DIR/jwt-cracker"
             success "Installed jwt-cracker"
             INSTALLED_TOOLS+=("jwt-cracker")
          else
             error "Failed to install jwt-cracker (fallback make failed)"
             FAILED_TOOLS+=("jwt-cracker")
          fi
       fi
     else
       error "Failed to install jwt-cracker (download failed)"
       FAILED_TOOLS+=("jwt-cracker")
     fi
     rm -rf "$BUILD_DIR"
  fi

   if [ ! -f "$BIN_DIR/hash-id.py" ]; then
     info "Installing hash-id.py..."
     if wget -q "https://raw.githubusercontent.com/blackploit/hash-identifier/master/hash-id.py" -O "$BIN_DIR/hash-id.py" 2>>"$LOG_FILE"; then
       chmod +x "$BIN_DIR/hash-id.py"
       success "Installed hash-id.py"
       INSTALLED_TOOLS+=("hash-id.py")
     else
       error "Failed to install hash-id.py"
       FAILED_TOOLS+=("hash-id.py")
     fi
  fi
 

   if ! "$PYTOOLS_VENV/bin/pip" show linkfinder >/dev/null 2>>"$LOG_FILE"; then
     info "Installing linkfinder..."
     if "$PYTOOLS_VENV/bin/pip" install "git+https://github.com/GerbenJavado/LinkFinder.git" >/dev/null 2>>"$LOG_FILE"; then
       success "Installed linkfinder"
       INSTALLED_TOOLS+=("linkfinder")
     else
       error "Failed to install linkfinder"
       FAILED_TOOLS+=("linkfinder")
     fi
   fi
   

   LF_SCRIPT=$(find "$PYTOOLS_VENV" -name linkfinder.py 2>/dev/null | head -n 1)
   if [ -n "$LF_SCRIPT" ]; then
     echo '#!/bin/bash' > linkfinder.tmp
     echo "exec \"$PYTOOLS_VENV/bin/python\" \"$LF_SCRIPT\" \"\$@\"" >> linkfinder.tmp
     cat linkfinder.tmp > "$BIN_DIR/linkfinder"
     chmod +x "$BIN_DIR/linkfinder"
     rm linkfinder.tmp
   fi


  if [ ! -f "$BIN_DIR/basic_scanner.py" ]; then
    info "Installing basic_scanner.py..."
    if wget -q "https://raw.githubusercontent.com/chikko80/Pen-Scripts/master/basic_scanner.py" -O "$BIN_DIR/basic_scanner.py" 2>>"$LOG_FILE"; then
      chmod +x "$BIN_DIR/basic_scanner.py"
      success "Installed basic_scanner.py"
      INSTALLED_TOOLS+=("basic_scanner.py")
    else
      error "Failed to install basic_scanner.py"
      FAILED_TOOLS+=("basic_scanner.py")
    fi
  fi
  if [ ! -f "$BIN_DIR/hydra_builder.py" ]; then
    info "Installing hydra_builder.py..."
    if wget -q "https://raw.githubusercontent.com/chikko80/Pen-Scripts/master/hydra_builder.py" -O "$BIN_DIR/hydra_builder.py" 2>>"$LOG_FILE"; then
      chmod +x "$BIN_DIR/hydra_builder.py"
      success "Installed hydra_builder.py"
      INSTALLED_TOOLS+=("hydra_builder.py")
    else
      error "Failed to install hydra_builder.py"
      FAILED_TOOLS+=("hydra_builder.py")
    fi
  fi
  if [ ! -f "$BIN_DIR/string_finder.py" ]; then
    info "Installing string_finder.py..."
    if wget -q "https://raw.githubusercontent.com/chikko80/Pen-Scripts/master/string_finder.py" -O "$BIN_DIR/string_finder.py" 2>>"$LOG_FILE"; then
      chmod +x "$BIN_DIR/string_finder.py"
      success "Installed string_finder.py"
      INSTALLED_TOOLS+=("string_finder.py")
    else
      error "Failed to install string_finder.py"
      FAILED_TOOLS+=("string_finder.py")
    fi
  fi

  "$PYTOOLS_VENV/bin/python" -m pip install -r "https://raw.githubusercontent.com/chikko80/Pen-Scripts/master/requirements.txt" >/dev/null 2>>"$LOG_FILE" || true
}

check_status() {
  local found=()
  local missing=()

  for pkg in "${BREW_FORMULAE[@]}"; do
    if brew list --formula "$pkg" >/dev/null 2>>"$LOG_FILE"; then
      found+=("$pkg")
    else
      missing+=("$pkg")
    fi
  done

  for pkg in "${BREW_CASKS[@]}"; do
    if brew list --cask "$pkg" >/dev/null 2>>"$LOG_FILE"; then
      found+=("$pkg")
    else
      missing+=("$pkg")
    fi
  done

  if [ -d "$PYTOOLS_VENV" ]; then
    for pkg in "${PIP3_PACKAGES[@]}"; do
      if "$PYTOOLS_VENV/bin/python" -m pip show "$pkg" >/dev/null 2>>"$LOG_FILE"; then
        found+=("$pkg")
      else
        missing+=("$pkg")
      fi
    done
  else
    for pkg in "${PIP3_PACKAGES[@]}"; do
      missing+=("$pkg")
    done
  fi

  printf "\n"
  info "Checking existing tools..."
  
  if [ "${#found[@]}" -gt 0 ]; then
    printf "${GREEN}[+] Found tools:${RESET}\n"
    local count=0
    for tool in "${found[@]}"; do
        printf "    %-25s" "$tool"
        ((count++))
        if [ $((count % 3)) -eq 0 ]; then printf "\n"; fi
    done
    [ $((count % 3)) -ne 0 ] && printf "\n"
  else
    warn "No tools found."
  fi
  
  printf "\n"

  if [ "${#missing[@]}" -gt 0 ]; then
    printf "${RED}[-] Missing tools:${RESET}\n"
     local count=0
    for tool in "${missing[@]}"; do
        printf "    %-25s" "$tool"
        ((count++))
        if [ $((count % 3)) -eq 0 ]; then printf "\n"; fi
    done
    [ $((count % 3)) -ne 0 ] && printf "\n"
  else
    success "No missing tools!"
  fi
}

check_status

printf "\n"
info "Starting installation process..."
printf "\n"

INSTALLED_TOOLS=()
FAILED_TOOLS=()


info "Installing Brew and Pip tools..."
for pkg in "${BREW_FORMULAE[@]}"; do
  install_brew_formula "$pkg"
done

for pkg in "${BREW_CASKS[@]}"; do
  install_brew_cask "$pkg"
done

for pkg in "${PIP3_PACKAGES[@]}"; do
  install_pip3_package "$pkg"
done

printf "\n"
info "Installing payload tools..."
install_payloads

printf "\n"
printf "${BOLD}${YELLOW}=== Summary ===${RESET}\n"

if [ "${#INSTALLED_TOOLS[@]}" -gt 0 ]; then
  printf "${GREEN}[+] Installed:${RESET}\n"
  local count=0
  for tool in "${INSTALLED_TOOLS[@]}"; do
      printf "    %-25s" "$tool"
      ((count++))
      if [ $((count % 3)) -eq 0 ]; then printf "\n"; fi
  done
  [ $((count % 3)) -ne 0 ] && printf "\n"
else
  warn "No new tools installed."
fi

printf "\n"

if [ "${#FAILED_TOOLS[@]}" -gt 0 ]; then
  printf "${RED}[-] Failed:${RESET}\n"
  local count=0
  for tool in "${FAILED_TOOLS[@]}"; do
      printf "    %-25s" "$tool"
      ((count++))
      if [ $((count % 3)) -eq 0 ]; then printf "\n"; fi
  done
  [ $((count % 3)) -ne 0 ] && printf "\n"
else
  success "No failures."
fi

printf "\n"
success "Installation Completed."
