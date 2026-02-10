#include "format.hpp"

#include <fcntl.h>        // open()
#include <unistd.h>       // close(), read(), write(), lseek()
#include <sys/ioctl.h>    // ioctl()
#include <linux/fs.h>     // BLK* ioctls

#include <linux/blkpg.h>  // GPT/MBR

#include <sys/wait.h>     // To invoke format helpers required to create filesystems
#include <spawn.h>        // To invoke format helpers required to create filesystems

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

static std::vector<std::string> drives;
static const std::string dev_path = std::string("/dev/");

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
}
