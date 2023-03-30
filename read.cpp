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
    if (getuid() != 0) {
        fprintf(stderr, "this program need root priv.. x)\n");
        return 1;
    }
    // 1. get katalk pid
    pid_t kakaotalk_pid = get_pid_from_name("KakaoTalk");
    if (kakaotalk_pid == 0) {
        perror("Can't found Kakaotalk");
        return 1;
    }
    printf("[+] kakaotalk pid : %d\n", kakaotalk_pid);


    kern_return_t kr;

    // 2. get task handle
    mach_port_t task;
    kr = task_for_pid(mach_task_self(), kakaotalk_pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[task_for_pid] failed : %s", mach_error_string(kr));
        return 1;
    }

    // 3. show mmap
    vm_address_t address = 0;
    vm_size_t size;
    vm_region_submap_info_data_64_t info;
    mach_port_t obj;
    mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    natural_t depth = 30;

    printf("       START-END             PRT/MAX    SHARE           REGION DETAIL\n");
    while (true) {
        kr = vm_region_recurse_64(task, &address, &size, &depth, (vm_region_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[vm_region_recurse_64] failed : %s", mach_error_string(kr));
            break;
        }


        char filename[2048];
        proc_regionfilename(kakaotalk_pid, address, filename, sizeof(filename));
        printf(
            "%012lx-%012lx    %s/%s    %-12s    %s\n", 
            address, 
            address + size, 
            rwx(info.protection).c_str(), 
            rwx(info.max_protection).c_str(),
            share_mode(info.share_mode).c_str(),
            filename
        );
        address += size;
    }


}
