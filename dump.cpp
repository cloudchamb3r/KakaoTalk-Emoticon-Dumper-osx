#include <memory>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <libproc.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <mach/mach_vm.h>

// global kernel return result
kern_return_t kr;

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

std::tuple<vm_address_t, vm_size_t, vm_prot_t> get_region_info(vm_map_read_t task, vm_address_t address) {
    vm_size_t size;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    natural_t depth = 30;

    kr = vm_region_recurse_64(task, &address, &size, &depth, (vm_region_info_t)&info, &cnt);
    if (kr != KERN_SUCCESS) {
        return {0, 0, 0};
    }
    return {address, size, info.protection};
}

int main() {
    // 1. check euid is root
    if (geteuid() != 0) {
        fprintf(stderr, "This program need root priv.. x)\n");
        return 1;
    }

    // 2. check kakaotalk process is existing
    pid_t kakaotalk_pid = get_pid_from_name("KakaoTalk");
    if (kakaotalk_pid == 0) {
        perror("Can't found Kakaotalk");
        return 1;
    }

    // 3. retreive kakaotalk task handle
    mach_port_t task;
    kr = task_for_pid(mach_task_self(), kakaotalk_pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[task_for_pid] failed : %s\n", mach_error_string(kr));
        return 1;
    }

    constexpr int riff_magic = 0x46464952;
    constexpr int webp_magic = 0x50424557;
    constexpr int mem_buffer_sz = 0x8000;
    auto mem_buffer = std::make_unique<char[]>(mem_buffer_sz);

    vm_address_t last_region_end = 0; 
    while (true) {
        auto [region_base, region_size, region_protection] = get_region_info(task, last_region_end);
        if (region_base == 0) {
            break;
        }
        printf("[+] inspecting %012lx-%012lx...\n", region_base, region_base + region_size);
        if ((region_protection & VM_PROT_READ) && !(region_protection & VM_PROT_EXECUTE) && (region_protection & SM_PRIVATE)) {
            size_t cursor = 0;
            while (cursor < region_size) {
                mach_vm_size_t rdbytes;
                kr = mach_vm_read_overwrite(task, region_base + cursor, mem_buffer_sz, (mach_vm_address_t)mem_buffer.get(), &rdbytes);
                if (kr != KERN_SUCCESS) break;
                
                // compare memory along 4byte align ;)
                for (auto offset = 0u ; offset + 8 < rdbytes; offset += 4) {
                    int _riff_magic = *((int*)(mem_buffer.get() + offset));
                    int _size = *((int*)(mem_buffer.get() + offset + 4));
                    int _webp_magic = *((int*)(mem_buffer.get() + offset + 8));
             
                    if (riff_magic == _riff_magic && webp_magic == _webp_magic && _size != 0) {         
                        auto webp_dump_size = _size + 12;
                        auto webp_dump = std::make_unique<char[]>(webp_dump_size);
                        mach_vm_size_t _dummy;
                        
                        kr = mach_vm_read_overwrite(task, region_base + cursor + offset, webp_dump_size, (mach_vm_address_t)webp_dump.get(), &_dummy);
                        if (kr != KERN_SUCCESS) continue;
                        
                        // dump
                        printf("[!] dumping on %012lx\n", region_base + cursor + offset);
                        std::ostringstream filename; filename << std::hex << region_base + cursor + offset << ".webp"; 
                        std::ofstream webp(filename.str(), std::ios_base::binary);
                        webp.write(webp_dump.get(), webp_dump_size);
                    }
                }

                cursor += rdbytes;
            }
        }
        last_region_end = region_base + region_size;
    }
}
