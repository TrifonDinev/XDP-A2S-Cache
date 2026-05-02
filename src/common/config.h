#pragma once

// Enable chain continuation for multiple XDP programs (1 = enable. 0 = disable).
#define XDP_MULTIPROG_ENABLED 1

// Program execution priority (lower values run earlier in the chain).
#define XDP_MULTIPROG_PRIORITY 10

// The action that indicates it should go onto the next program (default XDP_PASS).
#define XDP_MULTIPROG_ACTION XDP_PASS

// Use A2S_DEBUG only for debugging purposes and disable in production, A2S_DEBUG will significantly decrease performance!
//#define A2S_DEBUG

/**
* Enables support for Non-Steam clients/emulators.
*
* BEWARE: Activating this feature disables the A2S_INFO challenge-response,
* this creates a vulnerability to spoofed A2S amplification DDoS attacks and not only.
*
* Keep this disabled if you don't need such things, otherwise you already know the risks.
* If your Non-Steam client supports the changes from 2020 (see references below),
* then you don't need to enable this, except if older Non-Steam client queries are not working.
*
* References:
* - https://steamcommunity.com/discussions/forum/14/2974028351344359625
* - https://steamcommunity.com/discussions/forum/14/2989789048633291344
*/
//#define A2S_NON_STEAM_SUPPORT

/**
* Enables support for game tracking websites, old query tools/scripts, which are still using the old FFFFFFFF challenge method.
* This is being used for A2S_PLAYER and A2S_RULES for the moment.
*
* Some game tracking websites can still use the old FFFFFFFF challenge method, in combination with 00000000 for game clients too.
* Server may show as offline in some game trackers and old query tools/scripts!
* Test and enable/disable for your case.
*
* If A2S_NON_STEAM_SUPPORT (above) is enabled, this is not required, but if you don't want to enable A2S_NON_STEAM_SUPPORT,
* and having problems with game tracking websites or old query tools/scripts, which still are using the FFFFFFFF challenge method, enable this.
*
* Default is the 00000000 challenge method only.
* Last tested/reviewed on: 01.05.2026
*/
//#define A2S_DUAL_CHALLENGE_SUPPORT

/**
* A2S_QUERY_TIME_SEC - Interval (in seconds) between A2S queries.
*
* Determines how frequently the program polls for data updates from the server(s).
* A value in the 5-10 seconds range is reasonable for fresher data I think so.
*
* BEWARE: Long caching data may be flagged as spoofed by some master servers (e.g., Steam master server), as far as I know!
*/
#define A2S_QUERY_TIME_SEC 5