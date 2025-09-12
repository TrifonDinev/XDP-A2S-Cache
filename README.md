# XDP A2S Cache
My old and basic XDP A2S Cache, designed primarily for Counter-Strike 1.6 and Counter-Strike 2 at first, but also supports some of the GoldSrc and Source 1/2 engine games, or some that are using [A2S queries](https://developer.valvesoftware.com/wiki/Server_queries).

> [!NOTE]
>
> Some things that are lacking or need improvement:
>
> - Fragmentation support: Currently, there's no support for handling fragmented UDP packets (AF_XDP needs to be implemented).
> - Query data method: The queries method/logic runs every 5 seconds (A2S_QUERY_TIME_SEC), but could be totally changed and optimized for better efficiency.
> - Blocking sockets (synchronous mode): At the moment, blocking sockets are used (with AF_INET), which means if one server times out, the entire query chain waits.

## Supporting and tested on:
| Game                               | Engine                |
|------------------------------------|-----------------------|
| Half-Life                          | GoldSrc               |
| Counter-Strike 1.6 (CS 1.6)        | GoldSrc               |
| Counter-Strike Condition Zero (CS:CZ) | GoldSrc            |
| Counter-Strike Source (CS:S)       | Source 1              |
| Counter-Strike Global Offensive (CS:GO) | Source 1         |
| Counter-Strike 2 (CS2)             | Source 2              |
| Team Fortress 2 (TF2)              | Source 1              |
| Left 4 Dead 2 (L4D2)               | Source 1              |
| Garry's Mod (GM)                   | Source 1              |
| Rust                               | Unity                 |
| Maybe more games...                | which are not tested...|

> [!CAUTION]
> Fragmentation support is currently lacking (AF_XDP needs to be implemented) for `A2S_PLAYERS` and `A2S_RULES`.
> (`A2S_INFO` responses are typically small and do not require fragmentation in 99% of cases.)
> To avoid incomplete responses, keep packet sizes below `A2S_MAX_SIZE` (currently set to `1400` bytes).

| A2S Query Type     | Description                              |
|--------------------|----------------------------------------------|
| A2S_INFO           | Retrieves information about the server including, but not limited to: its name, the map currently being played, and the number of players. |
| A2S_PLAYERS        | List of players currently in the server.     |
| A2S_RULES          | Returns the server rules, or configuration variables in name/value pairs. |

> [!NOTE]
> Some games may use only `A2S_INFO`, so you can edit the code to drop and not query `A2S_PLAYERS` and `A2S_RULES`.
> `A2S_RULES` are not used or working in some games and you can adjust the code to drop it and not query it at all (I don't know who are still using it and where it is still needed).
> The fragmentation is guaranteed in CS 1.6 for example, broken/deprecated in CS:GO since (1.32.3.0, Feb 21, 2014 update) incl. CS2 as far as I know.

## Currently, it works as:
A config file with interface name and servers to be set up under /etc/xdpa2scache.
\
Upon start, the program will try to load in Driver mode (Native), if there is no driver support ([NIC driver XDP support list](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp)), it will fall back to SKB mode (Generic).
\
The servers are queried every 5 seconds for data (adjustable by `A2S_QUERY_TIME_SEC`)

## Requirements:
- A distribution with recommended Linux Kernel >= 5.15

- Tested on:
  - Debian 12 / 13 (12 September 2025, latest updates)
  - Ubuntu 24.04 / 25.04 (12 September 2025, latest updates)

- Ensure the following packages are installed:
These packages are installed via `apt` (Ubuntu, Debian, etc.), or similar package names in other package managers.
```bash
# Install dependencies.
sudo apt install -y clang llvm build-essential libconfig-dev libelf-dev libpcap-dev m4 gcc-multilib

# We need tools for our kernel since we need BPFTool.
# If there are no available, try to build BPFTool from source (https://github.com/libbpf/bpftool)
# For Debian 12/13 (which I mainly use) I build it from source
sudo apt install -y linux-tools-$(uname -r)
```

## Building:
Use `make` command to build.

## Running:
1. Make sure your interface is set up in `/etc/xdpa2scache/config`
2. Make sure your server(s) ip and port are set
3. Use `service xdpa2scache start` or `systemctl xdpa2scache start`
 - To enable service on boot: `systemctl enable xdpa2scache.service`

## License:
Licensed under the [MIT License](LICENSE).