<!-- markdownlint-configure-file {
  "MD013": {
    "code_blocks": false,
  },
  "MD013": false,
  "MD033": false,
  "MD041": false,
} -->

<div align="center">

# Cinema

Cinema is a **browserless multiviewer** with custom layouts.  
Drive multiple media sources (streams, videos, local files) with a single click or terminal command.

[Features](#features) •
[Quick start](#quick-start) •
[Using Cinema](#using-cinema) •
[Compilation](#compilation) •
[Contributing](#Contributing)

[![C][c-badge]][c]
[![Release][release-badge]][releases]
[![License][license-badge]][license]

[c-badge]: https://img.shields.io/badge/builtwith-C11-00599C?logo=C&logoColor=white&style=flat-square
[c]: https://www.c-language.org/

[release-badge]: https://img.shields.io/github/v/release/marm00/cinema?logo=github&logoColor=white&style=flat-square&color=44BB00
[releases]: https://github.com/marm00/cinema/releases

[license-badge]: https://img.shields.io/github/license/marm00/cinema?logo=MIT&logoColor=white&style=flat-square&color=DD4343
[license]: ./LICENSE

![Demo gif using Cinema to change layouts and shuffle media](./cinema.webp)

</div>

## Features

* Multiviewer for [mpv](https://github.com/mpv-player/mpv/)-supported media, including Twitch streams.
* Instant search across your files, and tags to group media.
* Save and load layouts (including [Chatterino](https://chatterino.com/)).
* Macros to do many things at once, optionally on startup.

## Quick start

Follow these steps to get started:

1. [Download the latest release](https://github.com/marm00/cinema/releases) for Windows or Linux on the GitHub releases page.
2. Run Cinema by double-clicking or from the command line.
3. Type `help` for a list of commands.

## Using Cinema

```sh
> layout 4            # play media on a 2x2 grid with Chatterino
> 2 twitch <channel>  # stream twitch <channel> on screen 2
> 1 3 search <term>   # play media matching <term> on screens 1 and 3
> tag <name>          # play media grouped by tag <name> on all screens

> l 3                 # commands have autocomplete: layout 3
> shuffle             # play the next file in tag/search/global
> autoplay 30         # play a new file every 30 seconds
> macro <name>        # process commands defined in macro one by one

>                     # empty commands default to shuffle
```

You have 2 options to create or change custom layouts. The first is to run `extra` to add screens, resize and move them (do the same with `chat`), and run `store <name>`. The second is to open [cinema.conf](./cinema.conf) (which has a short tutorial), find or add the layout, and manually set the expected fields (name, screen, chat).

If you're on a single-monitor setup and/or your console gets pushed below mpv, try setting it to be 'always on top' or modify the ['ontop'](https://mpv.io/manual/stable/#options-ontop) setting in mpv.conf.

## Compilation

On Windows run: `.\build.bat`

On Linux run:: `./build.sh`

**Windows:** Make sure you have installed [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2026) (select 'Desktop development with C++' when prompted) and [LLVM](https://github.com/llvm/llvm-project/releases/latest) (recommend 'add to PATH' option). The [RAD Debugger](https://github.com/EpicGamesExt/raddebugger) is recommended for development.

**MacOS**: untested, some functions are maybe not posix-compliant.

It builds in debug mode with openmp enabled by default. For the release version, run `build release`. To disable openmp, run `build nomp`. To enable address sanitizer, run `build asan`. Specify the log level with `build log_[X]` where [X] is one of *trace*, *debug* (default for debug builds), *info*, *warning* (default for release builds), *error*, descending in frequency.

## Contributing

Pull requests and issues are always welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) to contribute and visit the [issue tracker](https://github.com/marm00/cinema/issues) here on GitHub to submit a bug report or request a feature.
