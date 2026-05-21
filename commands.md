<!-- markdownlint-configure-file {
  "MD033": false,
} -->

# List of commands

Command format: `[<screens> <command> <arguments>]`.

All commands use autocomplete, including for custom layouts, tags, and macros.

```sh
> 2 4 search foo  # plays file names containing foo on screens 2 and 4. 
> autoplay        # enables autoplay for all screens.
```

Below is a list of all commands, alphabetically sorted. The list covers the same commands as running `help` but with more information. Optional arguments are enclosed in `[<...>]`, required arguments are enclosed in `<...>` (no brackets).

<hr/>

**[&lt;screens&gt;] autoplay [&lt;seconds&gt;]**  
&nbsp;&nbsp;&nbsp;&nbsp; Autoplay media. &lt;seconds&gt; can be 0 (turn off autoplay), greater than 0 (shuffle every &lt;seconds&gt; seconds), or not provided (shuffles when video ends or image was shown for 5 seconds).

**chat**  
&nbsp;&nbsp;&nbsp;&nbsp; Show or reposition chat. You can move the screen and use the `store` command to save the updated location and size.

**[&lt;screens&gt;] clear**  
&nbsp;&nbsp;&nbsp;&nbsp; Clear the current tag or search term. This restores the default playlist.

**[&lt;screens&gt;] copy**  
&nbsp;&nbsp;&nbsp;&nbsp; Copy url(s) to clipboard. The clipboard contents are formatted in support of <a href="https://www.voidtools.com/faq/#searching">Everything</a>. Does not copy on posix, only print.

**extra**  
&nbsp;&nbsp;&nbsp;&nbsp; Adds an extra screen to the current layout. You can use the `store` command to update the layout beyond this session.

**help**  
&nbsp;&nbsp;&nbsp;&nbsp; Show all commands.

**hide &lt;term&gt;**  
&nbsp;&nbsp;&nbsp;&nbsp; Hide media with &lt;term&gt;. Future `store` commands will not return hidden files. This can be used to exclude specific file extensions, for example.

**idle**  
&nbsp;&nbsp;&nbsp;&nbsp; Make commands (not) play media. Toggle whether a command is allowed to play media (`idle tag art idle` would update the tag but not play a new file).

**[&lt;screens&gt;] kill**  
&nbsp;&nbsp;&nbsp;&nbsp; Kill &lt;screens&gt; and chat. Closes the screens and Chatterino, without exiting Cinema (use the `quit` command to kill everything and exit).

**layout [&lt;name&gt;]**  
&nbsp;&nbsp;&nbsp;&nbsp; Change the current layout to &lt;name&gt;. Sets up screens and chat.

**list**  
&nbsp;&nbsp;&nbsp;&nbsp; Show all tags.

**[&lt;screens&gt;] lock**  
&nbsp;&nbsp;&nbsp;&nbsp; Lock/unlock screen contents. Toggle whether a screen is allowed to play new files. Would ignore things like *autoplay*, *shuffle*, *tag* if enabled.

**macro [&lt;name&gt;]**  
&nbsp;&nbsp;&nbsp;&nbsp; Execute macro. Processes a macro command by command. Macros are stored in cinema.conf.

**[&lt;screen&gt;] maximize**  
&nbsp;&nbsp;&nbsp;&nbsp; Maximize and close others. Kills all screens except &lt;screen&gt; or first and sets it to fullscreen.

**[&lt;screens&gt;] mute**  
&nbsp;&nbsp;&nbsp;&nbsp; Mute/unmute screen(s). This is a toggle.

**quit**  
&nbsp;&nbsp;&nbsp;&nbsp; Close screens and chat, then exit Cinema.

**[&lt;screens&gt;] search [&lt;term&gt;]**  
&nbsp;&nbsp;&nbsp;&nbsp; Limit media to &lt;term&gt;. Searches through all directories and urls in cinema.conf. Example searches: `1 s C:`, `2 3 s foo`, `s .mp4`, `s /bar/baz/`.

**[&lt;screens&gt;] shuffle**  
&nbsp;&nbsp;&nbsp;&nbsp; Shuffle media. Plays a new file. This is the default autocomplete command.

**store [&lt;layout name&gt;]**  
&nbsp;&nbsp;&nbsp;&nbsp; Store layout in cinema.conf with *name = &lt;layout name&gt;*. Creates or updates the layout in cinema.conf.

**[&lt;screen1 screen2&gt;] swap**  
&nbsp;&nbsp;&nbsp;&nbsp; Swap screen contents. Makes &lt;screen1&gt; play the media of &lt;screen2&gt; and vice versa.

**[&lt;screens&gt;] tag [&lt;name&gt;]**  
&nbsp;&nbsp;&nbsp;&nbsp; Limit media to &lt;tag&gt;. Tags group media, stored in cinema.conf.

**[&lt;screens&gt;] twitch [&lt;name&gt;]**  
&nbsp;&nbsp;&nbsp;&nbsp; Show channel &lt;name&gt;. Shortcut to watch a specific stream.
