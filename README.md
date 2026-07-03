# injectexe
poc allowing you to inject executeable files as if they were dlls.

the core of this project is almost 1:1 with https://github.com/moonlightrblx/telepathy/

# how it works

its a normal manual mapper but instead of mapping an entire file we map 2 things

1. the function that we want to inject from another exe

2. the shellcode loader to call said function

---
# how would you get this to work for any process:

change the shellcode loader to call a function with 0 args (you can ignore the ret value)

set the function resolver to resolve "main" instead of "injectexe_entry"

move the code you want to run in the injected process inside of main instead of the entry

viola :)

