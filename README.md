# injectexe
poc allowing you to inject executable files as if they were dlls.

the core of this project is almost 1:1 with https://github.com/sophiedacat/telepathy/

# how it works

1. find the target process by name and grab its pid
2. read the target exe from disk and validate the headers
3. allocate memory in the target for the image, the map data, and the loader
4. write the image headers and every section into the target
5. write a small loader stub plus a `manual_map_data` struct into the target
6. create a remote thread that runs the loader stub

the loader stub does the actual mapping work inside the target:
- applies base relocations if the image did not land at its preferred base
- walks the import directory and resolves every thunk via `LoadLibraryA` / `GetProcAddress`
- runs tls callbacks if present
- calls the exe entrypoint which continues as normal

after the thread returns the loader and map data are freed the mapped image stays because it is the exe.

# usage

```cpp
c_inject inj;
if (!inj.attach("target.exe")) return 1;
inj.manual_map("example.exe", "injectexe_entry");
```

- `attach` takes the process name and sets `pid`
- `manual_map` takes the exe to inject and the export name to call
- the export must be present in the local copy of the exe so we can compute its offset then apply it to the remote base
- `injectexe_entry` is the default export name you can point it at `main` if the exe exports it

# notes
- the exe must export the entry you want to call so we can resolve its offset locally
- the loader stub is position independent by construction
- section raw data bounds are checked before copying so a malformed exe cannot overrun the buffer
- does not free the mapped image (can cause detections but i doubt it matters if you're using this)
