#define EXPORT __attribute__((visibility("default")))
#include <mach/mach.h>
#include <unistd.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <stdio.h>
#include <mach-o/loader.h>
kern_return_t
find_main_binary(pid_t pid, mach_vm_address_t *main_address);

EXPORT int vm_read_wrapper
(
 unsigned int target_task,
 unsigned long address,
 unsigned long size,
 unsigned long *data,
 unsigned int *dataCnt
 )
{
	return vm_read(target_task, address, size, data, dataCnt);
}

EXPORT int task_for_pid_wrapper(unsigned int process, unsigned int* tout)
{
	return task_for_pid(current_task(), process, tout);
}

EXPORT int mach_vm_region_recurse_wrapper(unsigned int pid, unsigned long long *vmoffset)
{
	int ret = find_main_binary(pid, vmoffset);
	printf("[dylib] ret: %d vmoffset1: %p \n", ret, vmoffset);
	fflush(stdout); 
	return ret;
}

/*
 * find main binary by iterating memory region
 * assumes there's only one binary with filetype == MH_EXECUTE
 */
kern_return_t
find_main_binary(pid_t pid, mach_vm_address_t *main_address)
{
  // get task for pid
  vm_map_t target_task = 0;
  kern_return_t kr;
  if (task_for_pid(mach_task_self(), pid, &target_task))
  {
    return KERN_FAILURE;
  }
  
  vm_address_t iter = 0;
  while (1)
  {
      struct mach_header mh = {0};
      vm_address_t addr = iter;
      vm_size_t lsize = 0;
      uint32_t depth;
      mach_vm_size_t bytes_read = 0;
      struct vm_region_submap_info_64 info;
      mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
      if (vm_region_recurse_64(target_task, &addr, &lsize, &depth, (vm_region_info_t)&info, &count))
      {
          break;
      }
      kr = mach_vm_read_overwrite(target_task, (mach_vm_address_t)addr, (mach_vm_size_t)sizeof(struct mach_header), (mach_vm_address_t)&mh, &bytes_read);
      if (kr == KERN_SUCCESS && bytes_read == sizeof(struct mach_header))
      {
          /* only one image with MH_EXECUTE filetype */
          if ( (mh.magic == MH_MAGIC || mh.magic == MH_MAGIC_64) && mh.filetype == MH_EXECUTE)
          {
              fprintf(stdout, "[dylib][DEBUG] Found main binary mach-o image @ %p!\n", (void*)addr);
              *main_address = addr;
              break;
          }
      }
      iter = addr + lsize;
  }
  return KERN_SUCCESS;
}
