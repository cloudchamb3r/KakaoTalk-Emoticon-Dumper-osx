#include <stdio.h>
#include <memory>
#include <sys/sysctl.h>
#include <libproc.h>
#include <string>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <fstream>
#include <sstream>

pid_t get_pid_from_name(const std::string& name) {
    size_t sz; 
    sysctlbyname("kern.proc.all", nullptr, &sz, nullptr, 0);
    auto total = sz / sizeof(kinfo_proc);
    auto procs = std::make_unique<kinfo_proc[]>(total);
    sysctlbyname("kern.proc.all", procs.get(), &sz, nullptr, 0);
    for (auto i = 0u ; i < total; i++) {
        const auto& pid = procs[i].kp_proc.p_pid;
        char _name[512]; proc_name(pid, _name, 512);
        if (name == _name) {
            return pid;
        }
    }
    return 0;
}


std::string rwx(vm_prot_t prot) {
    char status[] = {'-', '-', '-', 0};
    if (prot & VM_PROT_READ) status[0] = 'r';
    if (prot & VM_PROT_WRITE) status[1] = 'w';
    if (prot & VM_PROT_EXECUTE) status[2] = 'x';
    return status;
}

std::string share_mode(unsigned char sm) {
    switch (sm)
    {
    case SM_COW:
        return "CoW";
    case SM_PRIVATE_ALIASED:
        return "PrivateAliased";
    case SM_PRIVATE:
        return "Private";
    case SM_EMPTY:
        return "Empty";
    case SM_SHARED_ALIASED:
        return "SharedAliased";
    case SM_SHARED:
        return "Shared";
    case SM_LARGE_PAGE:
        return "LargePage";
    case SM_TRUESHARED:
        return "TrueShared";
    default:
        return "Unknown";
    }
}

int main(int argc, char** argv) {
    if (geteuid() != 0) {
        fprintf(stderr, "this program need root priv.. x)\n");
        return 1;
    }
    pid_t kakaotalk_pid = get_pid_from_name("KakaoTalk");
    if (kakaotalk_pid == 0) {
        perror("Can't found Kakaotalk");
        return 1;
    }
    printf("[+] kakaotalk pid : %d\n", kakaotalk_pid);


    kern_return_t kr;

    mach_port_t task;
    kr = task_for_pid(mach_task_self(), kakaotalk_pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[task_for_pid] failed : %s\n", mach_error_string(kr));
        return 1;
    }

    vm_size_t max_size = 0; 
    vm_size_t size;
    vm_region_submap_info_data_64_t info;
    mach_port_t obj;
    mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    natural_t depth = 30;

    int riff_magic = 0x46464952;
    int webp_magic = 0x50424557;
    char * dump = new char[0x8000];

    for (vm_address_t address = 0; true ; address += size) {
        kr = vm_region_recurse_64(task, &address, &size, &depth, (vm_region_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[vm_region_recurse_64] failed : %s\n", mach_error_string(kr));
            break;
        }
        if ((info.protection & VM_PROT_READ) && !(info.protection & VM_PROT_EXECUTE) && (info.protection & SM_PRIVATE)) {
            size_t rdbytes = 0;
            while (rdbytes < size) {
                mach_vm_size_t _rdbytes;
                kr = mach_vm_read_overwrite(task, address + rdbytes, 0x8000, (mach_vm_address_t)dump, &_rdbytes);
                if (kr != KERN_SUCCESS) {
                    break;
                }

                for (auto offset = 0ul ; offset + 8 < _rdbytes; offset += 4) {
                    int cur = *((int*)(dump + offset));
                    if (cur == riff_magic) {
                        int next = *((int*)(dump + offset + 8));
                        if (next == webp_magic) {
                            int sz = *((int*)(dump + offset + 4)) + 12;
                            if (sz <= 12) continue;

                            char* webp_dump = new char[sz];
                            mach_vm_size_t dummy;
                            kr = mach_vm_read_overwrite(task, address + rdbytes + offset, sz, (mach_vm_address_t)webp_dump, &dummy);
                            if (kr != KERN_SUCCESS) continue;
                            
                            // dump
                            printf("[!] dumping..... on %012lx\n", address + rdbytes + offset);
                            std::ostringstream filename; filename << std::hex << address + rdbytes + offset << ".webp"; 
                            std::ofstream webp(filename.str(), std::ios_base::binary);
                            webp.write(webp_dump, sz);
                        }
                    }
                }
                rdbytes += _rdbytes;            
            }
        }
    }
}
