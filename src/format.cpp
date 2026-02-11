#include "format.hpp"

#include <fcntl.h>        // open()
#include <unistd.h>       // close(), read(), write(), lseek()
#include <spawn.h>        // To invoke format helpers required to create filesystems

#include <linux/fs.h>     // BLK* ioctls
#include <linux/blkpg.h>  // GPT/MBR
#include <linux/nvme_ioctl.h>


#include <sys/ioctl.h>    // ioctl()
#include <sys/wait.h>     // To invoke format helpers required to create filesystems
#include <sys/mount.h>    // Mount and unmount
#include <sys/file.h>   // flock()
#include <sys/stat.h>

#include <libudev.h>
#include <blkid/blkid.h>
#include <dirent.h>

#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include <cinttypes>
#include <cstring>
#include <array>
#include <thread>
#include <iostream>

static std::string selected_drive = "\0";

static std::vector<std::string> drives;
static const std::string dev_path = std::string("/dev/");

static constexpr size_t BUFFER_SIZE = 4 * 1024 * 1024; // 4MB

static bool key_equals(const ArgMap& arg, const char* literal) {
    size_t lit_len = strlen(literal);

    // literal must fit
    if (lit_len >= 256)
        return false;

    // bytes must match
    if (memcmp(arg.key, literal, lit_len) != 0)
        return false;

    // ensure no extra characters in key
    return arg.key[lit_len] == '\0';
}

static std::vector<std::string> list_drives() {
    std::vector<std::string> drives;
    DIR* dir = opendir("/sys/block");
    dirent* ent;

    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        drives.emplace_back(ent->d_name);  // sda, nvme0n1, mmcblk0
    }

    closedir(dir);
    return drives;
}

static bool is_removable(const std::string& disk) {
    std::ifstream f("/sys/block/" + disk + "/removable");
    int v = 0;
    f >> v;
    return v == 1;
}

static bool is_virtual_block(const std::string& disk) {
    std::string path = "/sys/block/" + disk + "/device";
    return access(path.c_str(), F_OK) != 0;
}

static std::string get_partition_table(const std::string& disk) {
    std::string dev = dev_path + disk;

    blkid_probe pr = blkid_new_probe_from_filename(dev.c_str());
    if (!pr)
        return "unknown";

    if (blkid_do_safeprobe(pr) != 0) {
        blkid_free_probe(pr);
        return "unknown";
    }

    const char* pttype = nullptr;
    if (blkid_probe_lookup_value(pr, "PTTYPE", &pttype, nullptr) == 0) {
        std::string result = pttype;
        blkid_free_probe(pr);
        return result == "dos" ? "MBR" :
               result == "gpt" ? "GPT" : result;
    }

    blkid_free_probe(pr);
    return "none";
}

static std::vector<std::string> list_volumes(const std::string& disk) {
    std::vector<std::string> vols;
    std::string path = "/sys/block/" + disk;

    DIR* dir = opendir(path.c_str());
    if (!dir)
        return vols;

    dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        std::string name = ent->d_name;

        if (name == "." || name == "..")
            continue;

        // partition names always start with disk name
        if (name.find(disk) == 0 && name != disk)
            vols.push_back(name);
    }

    closedir(dir);
    return vols;
}

static void print_volume_info(const std::string& volume) {
    std::string dev = dev_path + volume;

    blkid_probe pr = blkid_new_probe_from_filename(dev.c_str());
    if (!pr)
        return;

    if (blkid_do_safeprobe(pr) != 0) {
        blkid_free_probe(pr);
        return;
    }

    const char* type = nullptr;
    const char* uuid = nullptr;
    const char* label = nullptr;

    blkid_probe_lookup_value(pr, "TYPE", &type, nullptr);
    blkid_probe_lookup_value(pr, "UUID", &uuid, nullptr);
    blkid_probe_lookup_value(pr, "LABEL", &label, nullptr);

    printf(
        " |\tVolume %s\n"
        " |\t |\tFilesystem: %s\n"
        " |\t |\tUUID: %s\n"
        " |\t |\tLabel: %s\n",
        volume.c_str(),
        type  ? type  : "none",
        uuid  ? uuid  : "none",
        label ? label : "none"
    );

    blkid_free_probe(pr);
}

static bool isBlockDevice(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0)
        throw std::runtime_error("Cannot stat device");

    return S_ISBLK(st.st_mode);
}

static bool isMounted(const std::string& device) {
    std::ifstream mounts("/proc/self/mounts");
    std::string line;

    while (std::getline(mounts, line)) {
        if (line.find(device) != std::string::npos)
            return true;
    }
    return false;
}


static int runMkfs(const std::string& device, const std::string& fsType) {
    pid_t pid = fork();
    if (pid == 0) {
        std::string mkfsCmd = "mkfs." + fsType;

        std::vector<char*> args = {
            const_cast<char*>(mkfsCmd.c_str()),
            const_cast<char*>("-F"),  // force
            const_cast<char*>("-E"),
            const_cast<char*>("lazy_itable_init=0,lazy_journal_init=0"),
            const_cast<char*>(device.c_str()),
            nullptr
        };

        execvp(mkfsCmd.c_str(), args.data());
        _exit(1);  // exec failed
    }

    int status;
    waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
}

static int runWipefs(const std::string& device) {
    pid_t pid = fork();
    if (pid == 0) {
        char* args[] = {
            const_cast<char*>("wipefs"),
            const_cast<char*>("-a"),
            const_cast<char*>(device.c_str()),
            nullptr
        };
        execvp("wipefs", args);
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
}

static int runBlkdiscard(const std::string& device) {
    pid_t pid = fork();
    if (pid == 0) {
        char* args[] = {
            const_cast<char*>("blkdiscard"),
            const_cast<char*>(device.c_str()),
            nullptr
        };
        execvp("blkdiscard", args);
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
}


void manualWipe(const std::string& device) {
    int fd = open(device.c_str(), O_WRONLY | O_DIRECT);
    if (fd < 0)
        throw std::runtime_error("Failed to open device");

    // Get device size
    uint64_t size = 0;
    if (ioctl(fd, BLKGETSIZE64, &size) != 0)
        throw std::runtime_error("Failed to get device size");

    // Allocate aligned buffer (required for O_DIRECT)
    void* buffer = nullptr;
    if (posix_memalign(&buffer, 4096, BUFFER_SIZE) != 0)
        throw std::runtime_error("posix_memalign failed");

    memset(buffer, 0, BUFFER_SIZE);

    uint64_t written = 0;

    while (written < size) {
        size_t toWrite = BUFFER_SIZE;
        if (written + toWrite > size)
            toWrite = size - written;

        ssize_t result = write(fd, buffer, toWrite);
        if (result < 0)
            throw std::runtime_error("Write failed");

        written += result;
    }

    fsync(fd);
    close(fd);
    free(buffer);
}

// false=HDD; true=SSD
static bool isSSD(const std::string& deviceName) {
    std::string path = "/sys/block/" + deviceName + "/queue/rotational";
    std::ifstream f(path);
    int rotational;
    f >> rotational;
    return rotational == 0;
}

static int runCommand(const std::vector<std::string>& args) {
    pid_t pid = fork();
    if (pid == 0) {
        std::vector<char*> cargs;
        for (const auto& s : args)
            cargs.push_back(const_cast<char*>(s.c_str()));
        cargs.push_back(nullptr);

        execvp(cargs[0], cargs.data());
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
}

static std::string runCommandCapture(const std::vector<std::string>& args) {
    std::string cmd;
    for (const auto& s : args) {
        cmd += s + " ";
    }

    std::array<char, 4096> buffer;
    std::string result;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe)
        throw std::runtime_error("popen failed");

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
        result += buffer.data();

    pclose(pipe);
    return result;
}

// Abomination. Don't read the code
static void ataSecureErase(const std::string& device) {
    const std::string password = "p";

    // Detect enhanced support
    std::string identifyOutput = runCommandCapture({
        "hdparm", "-I", device
    });

    bool enhancedSupported = false;

    if (identifyOutput.find("supported: enhanced erase") != std::string::npos ||
        identifyOutput.find("Enhanced erase") != std::string::npos)
    {
        enhancedSupported = true;
    }

    // Set password
    if (runCommand({
        "hdparm",
        "--user-master", "u",
        "--security-set-pass", password,
        device
    }) != 0)
        throw std::runtime_error("Failed to set ATA password");

    // Perform erase (enhanced if available)
    std::vector<std::string> eraseCmd = {
        "hdparm",
        "--user-master", "u"
    };

    if (enhancedSupported)
        eraseCmd.push_back("--security-erase-enhanced");
    else
        eraseCmd.push_back("--security-erase");

    eraseCmd.push_back(password);
    eraseCmd.push_back(device);

    if (runCommand(eraseCmd) != 0)
        throw std::runtime_error("ATA secure erase failed");
}

static void ataSanitizeBlockErase(const std::string& device) {
    if (runCommand({
        "hdparm",
        "--sanitize-block-erase",
        device
    }) != 0)
        throw std::runtime_error("ATA sanitize block erase failed");
}

static void ataSanitizeCryptoErase(const std::string& device) {
    if (runCommand({
        "hdparm",
        "--sanitize-crypto-erase",
        device
    }) != 0)
        throw std::runtime_error("ATA sanitize crypto erase failed");
}

// Dont call directly
static void deleteScsiDevice(const std::string& deviceName) {
    std::string path = "/sys/block/" + deviceName + "/device/delete";
    std::ofstream ofs(path);
    if (!ofs)
        throw std::runtime_error("Failed to open delete path");

    ofs << "1";
}

// Dont call directly
static void rescanScsiHosts() {
    for (int i = 0; i < 16; ++i) {
        std::string path = "/sys/class/scsi_host/host" + std::to_string(i) + "/scan";
        std::ofstream ofs(path);
        if (ofs)
            ofs << "- - -";
    }
}

// Use this instead of the previous two
static void resetSataDevice(const std::string& deviceName) {
    deleteScsiDevice(deviceName);
    sleep(1);
    rescanScsiHosts();
}

static void nvmeSanitize(const std::string& controllerPath, uint8_t sanitizeAction) {
    if (sanitizeAction < 1 || sanitizeAction > 4)
        throw std::invalid_argument("Invalid sanitize action (1-4)");

    int fd = open(controllerPath.c_str(), O_RDWR);
    if (fd < 0)
        throw std::runtime_error("Failed to open NVMe controller");


    
    // Identify Controller



    std::vector<uint8_t> identify(4096, 0);

    nvme_admin_cmd identifyCmd{};
    identifyCmd.opcode   = 0x06;        // Identify
    identifyCmd.addr     = (uint64_t)identify.data();
    identifyCmd.data_len = identify.size();
    identifyCmd.cdw10    = 1;           // CNS=1 (Identify Controller)

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &identifyCmd) < 0) {
        close(fd);
        throw std::runtime_error("NVMe identify failed");
    }

    // SANICAP field offset 331-332 (little endian)
    uint16_t sanicap = *(uint16_t*)(&identify[331]);

    bool blockSupported  = sanicap & (1 << 1);
    bool overwriteSupported = sanicap & (1 << 2);
    bool cryptoSupported = sanicap & (1 << 3);

    if (sanitizeAction == 2 && !blockSupported) {
        close(fd);
        throw std::runtime_error("Block erase not supported");
    }

    if (sanitizeAction == 3 && !overwriteSupported) {
        close(fd);
        throw std::runtime_error("Overwrite not supported");
    }

    if (sanitizeAction == 4 && !cryptoSupported) {
        close(fd);
        throw std::runtime_error("Crypto erase not supported");
    }



    // Issue Sanitize Command



    nvme_admin_cmd sanitizeCmd{};
    sanitizeCmd.opcode = 0x84;  // Sanitize
    sanitizeCmd.cdw10  = sanitizeAction; // SANACT field

    if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &sanitizeCmd) < 0) {
        close(fd);
        throw std::runtime_error("Sanitize command failed");
    }



    // Poll Sanitize Status Log



    // Log page 0x81 = Sanitize Status
    std::vector<uint8_t> logPage(512, 0);

    while (true) {

        nvme_admin_cmd logCmd{};
        logCmd.opcode   = 0x02;        // Get Log Page
        logCmd.addr     = (uint64_t)logPage.data();
        logCmd.data_len = logPage.size();
        logCmd.cdw10    = (0x81 << 16) | (logPage.size() / 4);

        if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &logCmd) < 0) {
            close(fd);
            throw std::runtime_error("Failed reading sanitize status");
        }

        uint16_t status = *(uint16_t*)(&logPage[0]);
        uint16_t progress = *(uint16_t*)(&logPage[2]);

        bool sanitizeInProgress = status & 0x1;
        bool sanitizeFailed     = status & 0x2;

        if (sanitizeFailed) {
            close(fd);
            throw std::runtime_error("Sanitize failed");
        }

        if (!sanitizeInProgress)
            break;

        // Optional: progress display
        std::cout << "\rSanitize progress: "
                  << (progress * 100 / 0xFFFF)
                  << "%" << std::flush;

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "\rSanitize complete.            \n";

    close(fd);
}

static void nvmeReset(const std::string& controllerPath) {
    int fd = open(controllerPath.c_str(), O_RDWR);
    if (fd < 0)
        throw std::runtime_error("Failed to open NVMe controller");

    if (ioctl(fd, NVME_IOCTL_RESET) < 0) {
        close(fd);
        throw std::runtime_error("NVMe reset failed");
    }

    close(fd);
}

// 0=NVMe, 1=SATA
static int detectDriveType(const std::string& devicePath) {
    // Extract block device name from /dev/xxx
    std::string devName = devicePath;
    if (devName.rfind("/dev/", 0) == 0)
        devName = devName.substr(5);

    std::string sysPath = "/sys/block/" + devName;

    char resolved[PATH_MAX];
    ssize_t len = readlink(sysPath.c_str(), resolved, sizeof(resolved) - 1);
    if (len < 0)
        throw std::runtime_error("Failed to resolve sysfs path");

    resolved[len] = '\0';
    std::string realPath(resolved);

    // NVMe devices live under nvme subsystem
    if (realPath.find("/nvme/") != std::string::npos)
        return 0;  // NVMe

    // SATA drives are under SCSI subsystem
    if (realPath.find("/ata") != std::string::npos ||
        realPath.find("/scsi") != std::string::npos)
        return 1;  // SATA (SCSI-based)

    // If neither detected, fallback: check if name starts with nvme
    if (devName.rfind("nvme", 0) == 0)
        return 0;

    // Default to SATA for unknown block devices
    return 1;
}



namespace fs {
    size_t get_drives(const ArgMap* argv, size_t argc) {
        std::vector<std::string> dv_type_filter;
        if (argc <= 1) {
            dv_type_filter.push_back("Removable");
            dv_type_filter.push_back("Memory Module");
            dv_type_filter.push_back("Installed");
        } else {
            for (int i = 1; i < argc; i++) {
                ArgMap arg = argv[i];
                if (key_equals(arg, "removable") || key_equals(arg, "external"))
                    dv_type_filter.push_back("Removable");
                else if (key_equals(arg, "ram"))
                    dv_type_filter.push_back("Memory Module");
                else if (key_equals(arg, "installed") || key_equals(arg, "host"))
                    dv_type_filter.push_back("Installed");
            }
        }

        printf("-- Drives --\n");
        
        drives = list_drives();

        for (const std::string& drive : drives) {
            std::string path = dev_path + drive;

            int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0)
                continue;

            uint64_t size_bytes = 0;
            int logical = 0, physical = 0;

            ioctl(fd, BLKGETSIZE64, &size_bytes);
            ioctl(fd, BLKSSZGET, &logical);
            ioctl(fd, BLKPBSZGET, &physical);

            close(fd);

            std::string pttype = get_partition_table(drive);

            const char* type = is_removable(drive) ? "Removable" : is_virtual_block(drive) ? "Memory Module" : "Installed";

            for (auto c : dv_type_filter) {
                if (strcmp(c.c_str(), type) == 0) {
                    goto goto_type_found_in_filters;
                }
            }

            continue;

            goto_type_found_in_filters:

            printf(
                "Disk %s\n"
                " |\tLogical Sector Size: %d bytes\n"
                " |\tPhysical Sector Size: %d bytes\n"
                " |\tDevice Size: %" PRIu64 " bytes\n"
                " |\tDevice Type: %s\n"
                " |\tPartition Table: %s\n",
                drive.c_str(),
                logical,
                physical,
                size_bytes,
                type,
                pttype.c_str()
            );

            auto volumes = list_volumes(drive);
            for (const auto& v : volumes)
                print_volume_info(v);

            printf("\n");
        }

        return drives.size();
    }

    size_t get_volumes(const ArgMap* argv, size_t argc) {
        std::vector<std::string> disks;
        if (argc <= 1)
            disks = list_drives();
        else {
            for (int i = 1; i < argc; i++) {
                disks.push_back(argv[i].key);
            }
        }

        unsigned char found = 0;

        for (std::string disk : disks) {
            if (list_volumes(disk).empty()) continue;
            found = 1;
            printf("Disk %s\n", disk.c_str());
            for (auto &volume : list_volumes(disk)) {
                print_volume_info(volume);
            }
        }

        if (found == 0) {
            printf("No volumes found.\n");
            return 1;
        }

        return 0;
    }

    size_t format(const ArgMap* argv, size_t argc) {
        unsigned char mode;
        char filesystem[257]{0};
        if (argc == 1) {
            mode = 1;
        } else {
            for (int i = 0; i < argc; i++) {
                if (key_equals(argv[1], "quick"))
                    mode = 0;
                else if (key_equals(argv[1], "full"))
                    mode = 1;
                else if (key_equals(argv[1], "crypto"))
                    mode = 2;
                else if (key_equals(argv[1], "fs") && argv[1].value_exists)
                    memcpy(filesystem, argv[1].value, 256);
            }
        }
        if (filesystem[0] == 0) {
            memcpy(filesystem, "ext4", 5);
        }

        switch (mode) {
            case 0:
                if (!isBlockDevice(selected_drive))
                    return 1;
                if (isMounted(selected_drive))
                    return 1;
                
                printf("Performing a quick format on drive %s\n", selected_drive);
                printf("/ Wiping file system\n");
                runWipefs(selected_drive);
                printf("\033[1A\033[2K+ Wiped file system\n");

                printf("/ Creating new file system\n");
                runMkfs(selected_drive, filesystem);
                printf("\033[1A\033[2K+ Created new file system\n");

                printf("Drive formatted!");
                break;
            
            // Full format
            case 1:
                if (!isBlockDevice(selected_drive))
                    return 1;
                if (isMounted(selected_drive))
                    return 1;

                printf("Performing a full format on drive %s\n", selected_drive);
                printf("/ Wiping file system\n");
                runWipefs(selected_drive);
                printf("\033[1A\033[2K+ Wiped file system\n");

                if (!isSSD(selected_drive))
        }
    }
}
