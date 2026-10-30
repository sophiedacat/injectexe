# injectexe
poc allowing you to inject executeable files as if they were dlls.

the core of this project is almost 1:1 with https://github.com/moonlightrblx/telepathy/

# how it works

its a normal manual mapper but instead of mapping an entire file we map 2 things

1. the function that we want to inject from another exe

2. the shellcode loader to call said function

---
