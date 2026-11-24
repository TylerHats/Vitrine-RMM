#pragma once

#include "posix_common.hpp"

#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>

#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

namespace vitrine_posix {

inline std::string runSimpleCmd(const std::string& cmd) {
  std::string out;
  FILE* fp = ::popen(cmd.c_str(), "r");
  if (!fp) return out;
  char buf[512];
  while (out.size() < 256 * 1024) {
    size_t n = std::fread(buf, 1, sizeof(buf), fp);
    if (n == 0) break;
    out.append(buf, n);
  }
  ::pclose(fp);
  return out;
}

inline bool pathExists(const std::string& p) {
  struct stat st{};
  return ::stat(p.c_str(), &st) == 0;
}

inline std::string readDmiStr(const std::string& name) {
  return trimStr(readTextFile("/sys/class/dmi/id/" + name));
}

struct TelemetrySampler {
  uint64_t prevCpuTotal = 0;
  uint64_t prevCpuIdle = 0;
  uint64_t prevNetRx = 0;
  uint64_t prevNetTx = 0;
  std::time_t prevNetTime = 0;

  void warm() {
#ifdef __linux__
    readProcCpuPercent();
    readProcNetRates();
#endif
  }

#ifdef __linux__
  int readProcCpuPercent() {
    std::string line;
    std::ifstream ifs("/proc/stat");
    if (!std::getline(ifs, line)) return 10;
    std::istringstream iss(line);
    std::string label;
    iss >> label;
    uint64_t val = 0, total = 0, idleAll = 0;
    int idx = 0;
    while (iss >> val) {
      total += val;
      if (idx == 3 || idx == 4) idleAll += val;
      idx++;
    }
    int pct = 10;
    if (prevCpuTotal > 0 && total > prevCpuTotal) {
      uint64_t dt = total - prevCpuTotal;
      uint64_t di = (idleAll >= prevCpuIdle) ? (idleAll - prevCpuIdle) : 0;
      double used = static_cast<double>(dt > di ? (dt - di) : 0) / static_cast<double>(dt) * 100.0;
      pct = std::max(1, std::min(100, static_cast<int>(used + 0.5)));
    } else {
      double loads[1] = {0.0};
      if (::getloadavg(loads, 1) == 1) {
        long cores = std::max(1L, ::sysconf(_SC_NPROCESSORS_ONLN));
        pct = std::max(1, std::min(100, static_cast<int>((loads[0] / static_cast<double>(cores)) * 100.0 + 0.5)));
      }
    }
    prevCpuTotal = total;
    prevCpuIdle = idleAll;
    return pct;
  }

  std::pair<double, double> readProcNetRates() {
    std::ifstream ifs("/proc/net/dev");
    std::string ln;
    std::getline(ifs, ln);
    std::getline(ifs, ln);
    uint64_t rx = 0, tx = 0;
    while (std::getline(ifs, ln)) {
      size_t col = ln.find(':');
      if (col == std::string::npos) continue;
      std::string iface = trimStr(ln.substr(0, col));
      if (iface == "lo") continue;
      std::istringstream iss(ln.substr(col + 1));
      uint64_t c0 = 0, skip = 0, c8 = 0;
      if (iss >> c0 >> skip >> skip >> skip >> skip >> skip >> skip >> skip >> c8) {
        rx += c0;
        tx += c8;
      }
    }
    std::time_t now = std::time(nullptr);
    double rxMbps = 0.0, txMbps = 0.0;
    if (prevNetTime > 0 && now > prevNetTime) {
      double dt = static_cast<double>(now - prevNetTime);
      if (rx >= prevNetRx) rxMbps = ((rx - prevNetRx) * 8.0) / (dt * 1000000.0);
      if (tx >= prevNetTx) txMbps = ((tx - prevNetTx) * 8.0) / (dt * 1000000.0);
    }
    prevNetRx = rx;
    prevNetTx = tx;
    prevNetTime = now;
    return {rxMbps, txMbps};
  }
#endif
};

inline std::vector<std::pair<std::string, std::string>> collectInstalledSoftwareList(const std::string& family) {
  std::vector<std::pair<std::string, std::string>> items;
#ifdef __APPLE__
  const char* appDirs[] = {"/Applications", "/System/Applications", nullptr};
  for (int i = 0; appDirs[i]; i++) {
    DIR* d = ::opendir(appDirs[i]);
    if (!d) continue;
    struct dirent* ent;
    while ((ent = ::readdir(d)) != nullptr && items.size() < 300) {
      std::string name = ent->d_name;
      if (name.size() > 4 && name.compare(name.size() - 4, 4, ".app") == 0) {
        items.emplace_back(name.substr(0, name.size() - 4), "installed");
      }
    }
    ::closedir(d);
  }
#else
  std::string out;
  if (family == "debian" && pathExists("/usr/bin/dpkg-query")) {
    out = runSimpleCmd("dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null | head -n 300");
  } else if (family == "rhel" && (pathExists("/usr/bin/rpm") || pathExists("/bin/rpm"))) {
    out = runSimpleCmd("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null | head -n 300");
  } else if (family == "arch" && pathExists("/usr/bin/pacman")) {
    out = runSimpleCmd("pacman -Q 2>/dev/null | tr ' ' '\\t' | head -n 300");
  }
  std::istringstream iss(out);
  std::string line;
  while (std::getline(iss, line) && items.size() < 300) {
    size_t tab = line.find('\t');
    if (tab != std::string::npos) {
      std::string n = trimStr(line.substr(0, tab));
      std::string v = trimStr(line.substr(tab + 1));
      if (!n.empty()) items.emplace_back(n, v);
    }
  }
#endif
  return items;
}

inline std::string getChassisLabel(int ct) {
  switch (ct) {
    case 3: return "Desktop";
    case 4: return "Low Profile Desktop";
    case 5: return "Pizza Box";
    case 6: return "Mini Tower";
    case 7: return "Tower";
    case 8: return "Portable";
    case 9: return "Laptop";
    case 10: return "Notebook";
    case 11: return "Hand Held";
    case 14: return "Sub Notebook";
    case 15: return "Space-saving";
    case 17: return "Main Server Chassis";
    case 23: return "Rack Mount Chassis";
    case 28: return "Blade";
    case 30: return "Tablet";
    case 31: return "Convertible";
    case 32: return "Detachable";
    case 35: return "Mini PC";
    case 36: return "Stick PC";
    default: return ct == 0 ? "Unknown" : ("Chassis #" + std::to_string(ct));
  }
}

inline std::string collectTelemetryPayload(
    TelemetrySampler& sampler,
    const std::string& deviceId,
    bool includeFullInventory,
    bool headlessMode,
    bool forEnrollOnly = false) {
#ifdef VITRINE_HEADLESS_ONLY
  headlessMode = true;
#endif
  struct utsname u{};
  ::uname(&u);
  char hbuf[256] = {0};
  ::gethostname(hbuf, sizeof(hbuf) - 1);
  std::string hostname = hbuf[0] ? std::string(hbuf) : "vitrine-host";

  int cpuUsage = 10;
  long cpuCores = std::max(1L, ::sysconf(_SC_NPROCESSORS_ONLN));
  int ramPct = 25;
  double ramTotalGb = 8.0, ramUsedGb = 2.0;
  int diskPct = 25;
  double diskTotalGb = 64.0, diskFreeGb = 48.0;
  double netRxMbps = 0.0, netTxMbps = 0.0;
  int64_t uptimeSec = 0;

  struct statvfs stfs{};
  if (::statvfs("/", &stfs) == 0 && stfs.f_blocks > 0) {
    double blkSz = static_cast<double>(stfs.f_frsize ? stfs.f_frsize : stfs.f_bsize);
    diskTotalGb = (static_cast<double>(stfs.f_blocks) * blkSz) / (1024.0 * 1024.0 * 1024.0);
    diskFreeGb = (static_cast<double>(stfs.f_bavail) * blkSz) / (1024.0 * 1024.0 * 1024.0);
    double usedRatio = static_cast<double>(stfs.f_blocks - stfs.f_bavail) / static_cast<double>(stfs.f_blocks);
    diskPct = std::max(1, std::min(100, static_cast<int>(usedRatio * 100.0 + 0.5)));
  }

  std::string osType;
  std::string osVer;
  std::string osBuild = u.release;
  std::string manufacturer;
  std::string model;
  std::string serialNum;
  std::string biosVer;
  std::string cpuModel = u.machine;
  std::string loggedUser;
  std::string edrName;
  std::string edrStatus = "Unmonitored";
  bool encrypted = false;
  bool rebootReq = false;
  std::string distroFamily = "linux";
  bool hasBattery = false;
  bool isVm = false;
  bool isHvHost = false;
  std::string hvVendor;
  int chassisType = 0;
  std::string osProductType = "server";

#ifdef __APPLE__
  osType = "macos";
  distroFamily = "macos";
  std::string prodVer = trimStr(runSimpleCmd("sw_vers -productVersion 2>/dev/null"));
  osVer = "macOS " + (prodVer.empty() ? std::string(u.release) : prodVer);
  manufacturer = "Apple Inc.";
  char modelBuf[128] = {0};
  size_t mLen = sizeof(modelBuf);
  if (::sysctlbyname("hw.model", modelBuf, &mLen, nullptr, 0) == 0) model = modelBuf;
  char cpuBuf[256] = {0};
  size_t cLen = sizeof(cpuBuf);
  if (::sysctlbyname("machdep.cpu.brand_string", cpuBuf, &cLen, nullptr, 0) == 0 && cpuBuf[0]) cpuModel = cpuBuf;

  uint64_t memBytes = 0;
  size_t memLen = sizeof(memBytes);
  if (::sysctlbyname("hw.memsize", &memBytes, &memLen, nullptr, 0) == 0 && memBytes > 0) {
    ramTotalGb = static_cast<double>(memBytes) / (1024.0 * 1024.0 * 1024.0);
  }
  double loads[1] = {0.0};
  if (::getloadavg(loads, 1) == 1) {
    cpuUsage = std::max(1, std::min(100, static_cast<int>((loads[0] / static_cast<double>(cpuCores)) * 100.0 + 0.5)));
  }
  struct timeval bt{};
  size_t btLen = sizeof(bt);
  if (::sysctlbyname("kern.boottime", &bt, &btLen, nullptr, 0) == 0 && bt.tv_sec > 0) {
    uptimeSec = std::max<int64_t>(0, static_cast<int64_t>(std::time(nullptr)) - bt.tv_sec);
  }
  std::string vmOut = runSimpleCmd("vm_stat 2>/dev/null");
  if (!vmOut.empty() && memBytes > 0) {
    uint64_t pageSize = 4096, freePages = 0;
    size_t psPos = vmOut.find("page size of ");
    if (psPos != std::string::npos) pageSize = std::strtoull(vmOut.c_str() + psPos + 13, nullptr, 10);
    for (const char* k : {"Pages free:", "Pages speculative:"}) {
      size_t kp = vmOut.find(k);
      if (kp != std::string::npos) freePages += std::strtoull(vmOut.c_str() + kp + std::strlen(k), nullptr, 10);
    }
    uint64_t freeB = freePages * pageSize;
    uint64_t usedB = (memBytes > freeB) ? (memBytes - freeB) : 0;
    ramUsedGb = static_cast<double>(usedB) / (1024.0 * 1024.0 * 1024.0);
    ramPct = std::max(1, std::min(100, static_cast<int>((static_cast<double>(usedB) / static_cast<double>(memBytes)) * 100.0 + 0.5)));
  }
  hasBattery = runSimpleCmd("pmset -g batt 2>/dev/null").find("InternalBattery") != std::string::npos;
  int vmmFlag = 0;
  size_t vmmLen = sizeof(vmmFlag);
  if (::sysctlbyname("kern.hv_vmm_present", &vmmFlag, &vmmLen, nullptr, 0) == 0 && vmmFlag == 1) isVm = true;
  if (toLowerAscii(model).find("virtualmac") != std::string::npos) isVm = true;
  osProductType = (toLowerAscii(model).rfind("xserve", 0) == 0) ? "server" : "workstation";
  encrypted = toLowerAscii(runSimpleCmd("fdesetup isactive 2>/dev/null")).find("true") != std::string::npos;
  if (pathExists("/Library/Apple/System/Library/CoreServices/XProtect.bundle")) {
    edrName = "Apple XProtect";
    edrStatus = "Healthy";
  }
  rebootReq = pathExists("/Library/Updates/ProductMetadata.plist") || pathExists("/var/db/.AppleUpgrade");
  if (!headlessMode) {
    loggedUser = trimStr(runSimpleCmd("stat -f %Su /dev/console 2>/dev/null"));
    if (loggedUser == "root" || loggedUser == "loginwindow") loggedUser.clear();
  }
#else
  osType = "linux";
  std::string osRel = readTextFile("/etc/os-release");
  std::string loOs = toLowerAscii(osRel);
  if (loOs.find("debian") != std::string::npos || loOs.find("ubuntu") != std::string::npos) distroFamily = "debian";
  else if (loOs.find("rhel") != std::string::npos || loOs.find("fedora") != std::string::npos || loOs.find("centos") != std::string::npos || loOs.find("almalinux") != std::string::npos || loOs.find("rocky") != std::string::npos) distroFamily = "rhel";
  else if (loOs.find("arch") != std::string::npos) distroFamily = "arch";
  else if (loOs.find("suse") != std::string::npos) distroFamily = "suse";
  {
    std::istringstream iss(osRel);
    std::string ln;
    while (std::getline(iss, ln)) {
      if (ln.rfind("PRETTY_NAME=", 0) == 0) {
        osVer = trimStr(ln.substr(12));
        if (osVer.size() >= 2 && osVer.front() == '"' && osVer.back() == '"') {
          osVer = osVer.substr(1, osVer.size() - 2);
        }
        break;
      }
    }
    if (osVer.empty()) osVer = std::string("Linux ") + u.release;
  }

  cpuUsage = sampler.readProcCpuPercent();
  auto netRates = sampler.readProcNetRates();
  netRxMbps = netRates.first;
  netTxMbps = netRates.second;

  {
    std::ifstream mifs("/proc/meminfo");
    std::string ln;
    uint64_t memTotalKb = 0, memAvailKb = 0, memFreeKb = 0;
    while (std::getline(mifs, ln)) {
      if (ln.rfind("MemTotal:", 0) == 0) memTotalKb = std::strtoull(ln.c_str() + 9, nullptr, 10);
      else if (ln.rfind("MemAvailable:", 0) == 0) memAvailKb = std::strtoull(ln.c_str() + 13, nullptr, 10);
      else if (ln.rfind("MemFree:", 0) == 0) memFreeKb = std::strtoull(ln.c_str() + 8, nullptr, 10);
    }
    if (memTotalKb > 0) {
      uint64_t avail = memAvailKb > 0 ? memAvailKb : memFreeKb;
      uint64_t usedKb = (memTotalKb > avail) ? (memTotalKb - avail) : 0;
      ramTotalGb = static_cast<double>(memTotalKb) / (1024.0 * 1024.0);
      ramUsedGb = static_cast<double>(usedKb) / (1024.0 * 1024.0);
      ramPct = std::max(1, std::min(100, static_cast<int>((static_cast<double>(usedKb) / static_cast<double>(memTotalKb)) * 100.0 + 0.5)));
    }
  }
  {
    std::string upStr = readTextFile("/proc/uptime");
    if (!upStr.empty()) uptimeSec = static_cast<int64_t>(std::strtod(upStr.c_str(), nullptr));
  }
  {
    std::ifstream cifs("/proc/cpuinfo");
    std::string ln;
    while (std::getline(cifs, ln)) {
      std::string lo = toLowerAscii(ln);
      if (lo.rfind("model name", 0) == 0 || lo.rfind("hardware", 0) == 0) {
        size_t cpos = ln.find(':');
        if (cpos != std::string::npos) {
          cpuModel = trimStr(ln.substr(cpos + 1));
          break;
        }
      }
    }
    std::string cpuFull = readTextFile("/proc/cpuinfo");
    if (cpuFull.find("hypervisor") != std::string::npos) isVm = true;
  }

  manufacturer = readDmiStr("sys_vendor");
  model = readDmiStr("product_name");
  serialNum = readDmiStr("product_serial");
  biosVer = readDmiStr("bios_version");
  std::string ctRaw = readDmiStr("chassis_type");
  if (!ctRaw.empty()) chassisType = std::atoi(ctRaw.c_str());

  if (DIR* psDir = ::opendir("/sys/class/power_supply")) {
    struct dirent* ent;
    while ((ent = ::readdir(psDir)) != nullptr) {
      if (std::strncmp(ent->d_name, "BAT", 3) == 0) {
        hasBattery = true;
        break;
      }
    }
    ::closedir(psDir);
  }

  std::string dv = trimStr(runSimpleCmd("systemd-detect-virt --vm 2>/dev/null"));
  if (!dv.empty() && dv != "none") {
    isVm = true;
    hvVendor = dv;
  }
  isHvHost = (!isVm) && (pathExists("/usr/bin/pveversion") || pathExists("/usr/sbin/libvirtd"));

#ifdef VITRINE_HEADLESS_ONLY
  osProductType = "server";
#else
  if (headlessMode) {
    osProductType = "server";
  } else {
    bool hasGui = pathExists("/usr/bin/gnome-shell") || pathExists("/usr/bin/plasmashell") ||
                  pathExists("/usr/bin/xfce4-session") || pathExists("/usr/bin/Xorg") ||
                  pathExists("/usr/sbin/gdm3") || pathExists("/usr/sbin/gdm") ||
                  pathExists("/usr/sbin/sddm") || pathExists("/usr/sbin/lightdm");
    if (!hasGui) {
      hasGui = trimStr(runSimpleCmd("systemctl get-default 2>/dev/null")) == "graphical.target";
    }
    bool laptopChassis = (chassisType == 8 || chassisType == 9 || chassisType == 10 || chassisType == 11 ||
                          chassisType == 14 || chassisType == 30 || chassisType == 31 || chassisType == 32);
    osProductType = (hasGui || hasBattery || laptopChassis) ? "workstation" : "server";
  }
#endif

  if (pathExists("/sys/module/apparmor")) edrName = "AppArmor";
  else if (pathExists("/sys/fs/selinux")) edrName = "SELinux";
  for (const char* svc : {"falcon-sensor", "mdatp", "sentinelagent", "wazuh-agent", "clamav-daemon"}) {
    std::string rc = trimStr(runSimpleCmd(std::string("systemctl is-active ") + svc + " 2>/dev/null"));
    if (rc == "active") {
      edrName = svc;
      break;
    }
  }
  edrStatus = edrName.empty() ? "Unmonitored" : "Healthy";

  std::string ctab = readTextFile("/etc/crypttab");
  if (!ctab.empty()) {
    std::istringstream iss(ctab);
    std::string ln;
    while (std::getline(iss, ln)) {
      std::string t = trimStr(ln);
      if (!t.empty() && t[0] != '#') { encrypted = true; break; }
    }
  }
  rebootReq = pathExists("/var/run/reboot-required") || pathExists("/run/reboot-required");
  loggedUser = trimStr(runSimpleCmd(
    "(loginctl list-sessions --no-legend 2>/dev/null | awk '$3 != \"\" && $3 != \"gdm\" && $3 != \"lightdm\" && $3 != \"sddm\" {print $3}'; "
    "who 2>/dev/null | while read -r u _r; do case \"$u\" in [0-9]*) id -nu \"$u\" 2>/dev/null;; *) [ -n \"$u\" ] && printf '%s\\n' \"$u\";; esac; done) "
    "| awk 'NF && !seen[$0]++' | paste -sd ', ' -"));
#endif

  std::string variantTag = headlessMode ? "posix-headless" :
#ifdef __APPLE__
    "macos-native";
#else
    "posix-desktop";
#endif

  char rTot[32], rUse[32], dTot[32], dFree[32], nRx[32], nTx[32];
  std::snprintf(rTot, sizeof(rTot), "%.2f", ramTotalGb);
  std::snprintf(rUse, sizeof(rUse), "%.2f", ramUsedGb);
  std::snprintf(dTot, sizeof(dTot), "%.2f", diskTotalGb);
  std::snprintf(dFree, sizeof(dFree), "%.2f", diskFreeGb);
  std::snprintf(nRx, sizeof(nRx), "%.3f", netRxMbps);
  std::snprintf(nTx, sizeof(nTx), "%.3f", netTxMbps);

  std::ostringstream js;
  js << "{";
  if (!forEnrollOnly && !deviceId.empty()) js << "\"deviceId\":\"" << jsonEscape(deviceId) << "\",";
  if (!forEnrollOnly) {
    js << "\"hostname\":\"" << jsonEscape(hostname) << "\","
       << "\"osType\":\"" << jsonEscape(osType) << "\","
       << "\"companionVersion\":\"3.0.0-posix\","
       << "\"agentVariant\":\"" << jsonEscape(variantTag) << "\",";
  } else {
    js << "\"agentVariant\":\"" << jsonEscape(variantTag) << "\",";
  }
  js << "\"osVersion\":\"" << jsonEscape(osVer) << "\","
     << "\"osBuild\":\"" << jsonEscape(osBuild) << "\","
     << "\"manufacturer\":\"" << jsonEscape(manufacturer) << "\","
     << "\"model\":\"" << jsonEscape(model) << "\","
     << "\"serialNumber\":\"" << jsonEscape(serialNum) << "\","
     << "\"biosVersion\":\"" << jsonEscape(biosVer) << "\","
     << "\"cpuModel\":\"" << jsonEscape(cpuModel) << "\","
     << "\"cpuCores\":" << cpuCores << ","
     << "\"ramTotalGb\":" << rTot << ","
     << "\"diskTotalGb\":" << dTot << ","
     << "\"diskFreeGb\":" << dFree << ",";

  if (!forEnrollOnly) {
    js << "\"cpuUsage\":" << cpuUsage << ","
       << "\"ramUsage\":" << ramPct << ","
       << "\"ramUsedGb\":" << rUse << ","
       << "\"diskUsage\":" << diskPct << ","
       << "\"netRxMbps\":" << nRx << ","
       << "\"netTxMbps\":" << nTx << ","
       << "\"uptimeSeconds\":" << uptimeSec << ","
       << "\"loggedInUser\":\"" << jsonEscape(loggedUser) << "\","
       << "\"edrStatus\":\"" << jsonEscape(edrStatus) << "\","
       << "\"edrName\":\"" << jsonEscape(edrName) << "\","
       << "\"avStatus\":\"" << jsonEscape(edrStatus) << "\","
       << "\"bitlockerEncrypted\":" << (encrypted ? "true" : "false") << ","
       << "\"bitlockerStatus\":\"" << (encrypted ? (distroFamily == "macos" ? "Encrypted" : "LUKS Encrypted") : "Unencrypted") << "\","
       << "\"rebootPending\":" << (rebootReq ? "true" : "false") << ","
       << "\"rebootRequired\":" << (rebootReq ? "true" : "false") << ",";
  }

  js << "\"hardwareDetails\":{"
     << "\"system\":{"
     << "\"manufacturer\":\"" << jsonEscape(manufacturer) << "\","
     << "\"model\":\"" << jsonEscape(model) << "\","
     << "\"serialNumber\":\"" << jsonEscape(serialNum) << "\","
     << "\"biosVersion\":\"" << jsonEscape(biosVer) << "\","
     << "\"chassisType\":" << chassisType << ","
     << "\"chassisLabel\":\"" << jsonEscape(getChassisLabel(chassisType)) << "\","
     << "\"hasBattery\":" << (hasBattery ? "true" : "false") << ","
     << "\"isVirtualMachine\":" << (isVm ? "true" : "false") << ","
     << "\"isHypervisorHost\":" << (isHvHost ? "true" : "false") << ","
     << "\"hypervisorVendor\":\"" << jsonEscape(hvVendor) << "\","
     << "\"osProductType\":\"" << jsonEscape(osProductType) << "\","
     << "\"distroFamily\":\"" << jsonEscape(distroFamily) << "\""
     << "},"
     << "\"os\":{"
     << "\"caption\":\"" << jsonEscape(osVer) << "\","
     << "\"version\":\"" << jsonEscape(osBuild) << "\","
     << "\"architecture\":\"" << jsonEscape(u.machine) << "\","
     << "\"uptimeSeconds\":" << uptimeSec << ","
     << "\"loggedInUser\":\"" << jsonEscape(loggedUser) << "\""
     << "},"
     << "\"cpu\":{"
     << "\"model\":\"" << jsonEscape(cpuModel) << "\","
     << "\"cores\":" << cpuCores << ","
     << "\"threads\":" << cpuCores
     << "},"
     << "\"memory\":{\"totalGb\":" << rTot << ",\"usedGb\":" << rUse << "}"
     << "}";

  if (!forEnrollOnly && includeFullInventory) {
    auto sw = collectInstalledSoftwareList(distroFamily);
    js << ",\"installedSoftware\":[";
    for (size_t i = 0; i < sw.size(); i++) {
      if (i > 0) js << ",";
      js << "{\"name\":\"" << jsonEscape(sw[i].first) << "\",\"version\":\"" << jsonEscape(sw[i].second) << "\"}";
    }
    js << "]";
  }

  js << "}";
  return js.str();
}

}  // namespace vitrine_posix

