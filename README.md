# frogprobe
frogprobe - like x86_64 kprobe but you can sleep in it

## Known Limitation:
- Funcitons with more than 6 parameters (parameters are on stack)
- Funcitons that already kprobes

## TODO:
- [ ] understand how kprobe force module to wait till no kprobes are running (and
      implement such thing if possible)
- [ ] Add optimization option to pass number of arguments function has
- [ ] Support Kprobed (as much as possible)
- [ ] speed up trampoline stubs (siwtch call + ret to 2 jmp, instead rip rel call, movabs + call, ....) and test if really helps
- [ ] Support hook functions which doesn't start enough space for call
- [ ] Implement trampoline using RETHUNK instead of 'ret; int3' (as done in frace create_trampoline)
