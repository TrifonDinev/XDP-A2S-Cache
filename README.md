# XDP A2S Cache
My old and basic XDP A2S Cache, designed primarily for Counter-Strike 1.6 and Counter-Strike 2 at first, with support for multiple servers, Steam and non-Steam clients, GoldSrc and Source 1/2 engine games, as well as some other games that support [A2S queries](https://developer.valvesoftware.com/wiki/Server_queries).

> [!NOTE]
>
> Some things that are lacking or need improvement:
> - Fragmentation/Split packets support: Currently, there's no support for handling fragmented UDP packets. AF_XDP and/or [Split packets](https://developer.valvesoftware.com/wiki/Server_queries#Multi-packet_Response_Format) needs to be reviewed for `A2S_PLAYERS` and `A2S_RULES`.
> - Query data method: The queries method/logic runs every 5 seconds (`A2S_QUERY_TIME_SEC`), but could be totally changed and optimized for better efficiency.
> - Blocking sockets (synchronous mode): At the moment, blocking sockets are used (with AF_INET), which means if one server times out, the entire query chain waits.
> ---
> Some games may only use `A2S_INFO` and `A2S_PLAYERS` queries (or even just `A2S_INFO`), so you can edit the code to drop the unnecessary queries and use only what’s needed.
>
> Useful information on fragmentation (current state):
> - `A2S_INFO`
>   - Responses are typically small and do not require fragmentation in 99% of cases.
>
> - `A2S_PLAYERS`
>   - Up to 32 players: Working fine (no fragmentation) with maximum player name length (e.g., max "ZZZZZZ"), tested in CS 1.6, or at least in this specific test case.
>   - For the 33-64 players range: Fragmentation depend on player name length. The exact player count limit with standard name lengths (not maximum) has not been tested, but `A2S_DEBUG` may be useful for your case.
>
> - `A2S_RULES`
>   - Not used or working in some games and you can adjust the code to drop it and not query it at all (I don't know who are still using it and where it is still needed).
>   - The fragmentation is guaranteed in CS 1.6 for example, broken/deprecated in CS:GO since (1.32.3.0, Feb 21, 2014 update) incl. CS2 as far as I know.
>
> To avoid incomplete responses at the moment, keep packet sizes below `A2S_MAX_SIZE` (currently set to `1400` bytes).

## Supporting and tested on:
| A2S Query Type     | Description                              |
|--------------------|----------------------------------------------|
| A2S_INFO           | Retrieves information about the server including, but not limited to: its name, the map currently being played, and the number of players. |
| A2S_PLAYERS        | List of players currently in the server.     |
| A2S_RULES          | Returns the server rules, or configuration variables in name/value pairs. |

| Game                               | Engine                |
|------------------------------------|-----------------------|
| Half-Life                          | GoldSrc               |
| Counter-Strike 1.6 (CS 1.6)        | GoldSrc               |
| Counter-Strike: Condition Zero (CS:CZ) | GoldSrc           |
| Counter-Strike: Source (CS:S)      | Source 1              |
| Counter-Strike: Global Offensive (CS:GO) | Source 1        |
| Counter-Strike 2 (CS2)             | Source 2              |
| Team Fortress 2 (TF2)              | Source 1              |
| Left 4 Dead 2 (L4D2)               | Source 1              |
| Garry's Mod (GM)                   | Source 1              |
| Half-Life 2 (HL2)                  | Source 1              |
| Day of Defeat: Source (DoD:S)      | Source 1              |
| Rust                               | Unity                 |
| Maybe more games...                | which are not tested...|

## Requirements:
1. A distribution with recommended Linux Kernel >= 5.15
 - Tested on:
   - Debian 12 / 13 (Last tested on: 1 February 2026, latest updates)
   - Ubuntu 24.04 / 25.04 (Last tested on: 1 February 2026, latest updates)

2. Ensure the following packages are installed:
- These packages are installed via `apt` (Ubuntu, Debian, etc.), or similar package names in other package managers.
```bash
# Install dependencies.
sudo apt install -y clang llvm build-essential libconfig-dev libelf-dev libpcap-dev m4 gcc-multilib

# We need tools for our kernel since we need BPFTool.
# If there are no available, try to build BPFTool from source (https://github.com/libbpf/bpftool)
# For Debian 12/13 (which I mainly use) I build it from source
sudo apt install -y linux-tools-$(uname -r)
```

If you are cloning this repository with Git, use the `--recursive` flag to download the XDP Tools submodule.
\
If you cloned the repository with Git and without `--recursive` flag, run the following command from the repository root: `git submodule update --init`

## Building/Installing:
Use `make` command to build.
\
Use `make install` command to install.

## Running:
1. Ensure that everything is properly configured in `/etc/xdpa2scache/config`, interface name and server(s) IP and port.

2. Start the service using: `service xdpa2scache start` or `systemctl start xdpa2scache`
\
(Optional) To enable the service to start automatically on boot, use: `systemctl enable xdpa2scache.service`

3. Upon start, the program will attempt to load in Driver mode (Native). If there is no driver support ([NIC driver XDP support list](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp)), it will fall back to SKB mode (Generic).

4. The program will query the servers every 5 seconds for data by default (this interval can be adjusted by modifying `A2S_QUERY_TIME_SEC`).

## FAQ:
Q: There is libxdp error when starting the program:
```bash
libxdp.so.1: cannot open shared object file: No such file or directory
```
A: 1. Refresh library cache (recommended), by using: `sudo ldconfig`
\
A: 2. If it doesn't work, try adding the library path manually if it is installed in /usr/local/lib by running: `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`

Q: There is error while installing bpftool from source: 
```bash
fatal error: openssl/opensslv.h: No such file or directory - 16 | #include <openssl/opensslv.h>
```
A: For Debian/Ubuntu, use: `sudo apt install libssl-dev`

## License:
Licensed under the [MIT License](LICENSE).