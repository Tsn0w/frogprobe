# frogprobe
frogprobe - like x86_64 kprobe but you can sleep in it

## Usage:
If you wish to use this probes in your modules, there is currently 1 option:
### In-source
if you want to use this in your source code, checkout at our [in_source](example/in_source) folder for the example, basically just copy the `frogprobe.c `, `encoder.c` and `symbol_extractor.c` into you src folder and their corresponding headers file to your include folder.

Note that `symbols_extractor.c/h` is not mandatory if you have your own way to export symbols.

## Known Limitation:
- Funcitons with more than 6 parameters (parameters are on stack)
- Funcitons that already kprobes

## TODO:
- [ ] Add optimization option to pass number of arguments function has
- [ ] Support Kprobed (as much as possible)
- [ ] speed up trampoline stubs (siwtch call + ret to 2 jmp, instead rip rel call, movabs + call, ....) and test if really helps
- [ ] Support hook functions which doesn't start enough space for call
- [ ] Implement trampoline using RETHUNK instead of 'ret; int3' (as done in frace create_trampoline)