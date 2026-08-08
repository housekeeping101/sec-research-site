#  Leaked Chinese (Korea Targeting) Linux Stealth Rootkit Analysis
https://sandflysecurity.com/blog/leaked-north-korean-linux-stealth-rootkit-analysis

```
stat /usr/lib64/tracker-fs 
file /usr/lib64/tracker-fs
```
The next sign of trouble is that the kernel module is not signed.
- https://sandflysecurity.com/blog/sandfly-4-3-2-linux-loadable-kernel-module-rootkit-taint-detection
These three commands will show taint status, or the deliberate loading of the module _vmwfxs_ which is the name used by this rootkit.

`dmesg | grep taint 
dmesg | grep vmwfxs 
grep taint /var/log/kern.log
`
`var/log/kern.log found on some systems`

enumerate the monitor and display 
active display being used
reporting back as external monitor with hardware limitation of fhd and operating in xga
secondary monitor setup as a mirror?
	low res
master mirror
