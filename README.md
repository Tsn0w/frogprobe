# frogprobe
frogprobe - like x86_64 kprobe but you can sleep in it

## API
the frogprobe API is documented [frogprobe.h](include/frogprobe.h) and it's contains
2 main functions:
1. register_frogprobe
2. unregister_frogprobe

which uses to apply and revert probes on sybmols, in order to register each frogprobe
requires symbol_name (the symbol you want to probe as shown at `/proc/kallsyms`) and
a pre_handler or a post_handler (or both).

check for example for more details.

## Usage in LKMs:
If you wish to use this probes in your modules, there is currently 2 options, in each you should run the [`dummy`](example/dummy) binary provided to trigger the frogprobes.
### 1. In-source
checkout at [in_source](example/in_source) folder for the example, just copy the `frogprobe.c `, `encoder.c` and `symbol_extractor.c` into you src folder and their corresponding headers file to your include folder (`symbols_extractor.c` is not mandatory if you have your own way to export symbols).
### 2. external-LKM (preferred)
checkout at [external_lkm](example/external_lkm). just type in terminal `make && sudo make install` and both of frogprobe.ko and frogprobe_user.ko will be installed, as the name implies, frogprobe.ko is the module contains the frogprobe logic, while frogprobe_user contain an example usage.


## Known Limitation:
- Funcitons with more than 6 parameters (parameters are on stack)
- Funcitons that already kprobes


## TODO:
- [ ] Add optimization option to pass number of arguments function has
- [ ] Support Kprobed (as much as possible)
- [ ] speed up trampoline stubs as much as possible
- [ ] Support hook functions which doesn't start enough space for call
- [ ] Implement trampoline using RETHUNK instead of 'ret; int3' (as done in frace create_trampoline)
