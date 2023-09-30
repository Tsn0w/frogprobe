# frogprobe
frogprobe - like x86_64 kprobe but you can sleep in it

## Known Limitation:
- Funcitons with more than 6 parameters (parameters are on stack)
- Funcitons that already kprobes

## TODO:
- [ ] Add optimization option to pass number of arguments function has
- [ ] Add ability to modify RIP
- [ ] Support Kprobed (as much as possible)
- [ ] support multiple frogprobe on the same function
- [ ] speed up trampoline stubs (siwtch call + ret to 2 jmp, instead rip rel call, movabs + call, ....) and test if really helps
- [ ] Support hook functions which doesn't start enough space for call
- [ ] switch stop_machine to text_poke (understand how it's works and why don't disable X86_64_WP cpu flag)
- [ ] Implement trampoline using RETHUNK instead of 'ret; int3' (as done in frace create_trampoline)
