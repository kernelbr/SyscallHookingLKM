SyscallHookingLKM
=================

An example of Syscall Hooking


```
# insmod syshook.ko sys_call_table_addr="0xffffffff81401200"
$ ./gccrun 'exit(3);' # yes, gcc generates code using sys_exit_group instead
$ dmesg | tail -n1
[ 2351.072440] Hooked sys_exit_group (3)
# rmmod syshook
```
