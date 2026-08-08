## codesign 
- codesign -dv /System/Applications/Automator.app
The -d (display) option with the v (verbose) option will display basic code signature information.

We can use -d with the --entitlements option to display the entitlements of the binary in a human-readable XML format.
- codesign -d --entitlements :- /System/Applications/Automator.app


## objdump 

The --dylibs-used option will print the dylibs loaded by the file. We will use our own toolsdemo sample here, to verify the dylibs are loaded
- objdump -m --dylibs-used toolsdemo

Using the -h or --section-headers will display information about the header of each section.
- objdump -m -h toolsdemo

The --syms option will present us with the symbol table, which contains the name of the external functions used by the binary. In some cases, like in our example, the internal function names are also available.
- objdump -m --syms toolsdemo

We can also dump raw data with the --full-contents option.
The --all-headers option will display all supported headers, including the regular Mach-O header and all of the load commands.
- objdump -m --full-contents toolsdemo