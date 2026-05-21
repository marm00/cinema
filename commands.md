<!-- markdownlint-configure-file {
  "MD033": false,
} -->

# List of commands

Commands are formatted as: `[<screens> <command> <arguments>]`. Both `<screens>` and `<arguments>` are almost always optional. All commands use autocomplete, including for custom layouts, tags, and macros.

```sh
> 2 4 search foo  # plays file names containing foo on screens 2 and 4. 
> autoplay        # enables autoplay for all screens.
```

Below is a list of all commands, alphabetically sorted. The list covers the same commands as running `help` but with more information. Optional arguments are enclosed in `[<...>]`, required arguments are enclosed in `<...>` (no brackets).

<hr/>

<dl>
  <dt><strong>[&lt;screens&gt;] autoplay [&lt;seconds&gt;]</strong></dt>
  <dd>Autoplay media. *Seconds* can be 0 (turn off autoplay), greater than 0 (shuffle every *seconds* seconds), or not provided (shuffles when video ends or image was shown for 5 seconds).</dd>

  <dt><strong>chat</strong></dt>
  <dd>Show or reposition chat. You can move the window and use the *store* command to save the updated location and size.</dd>

  <dt><strong>[&lt;screens&gt;] clear</strong></dt>
  <dd>Clear the current tag or search term. This restores the default playlist.</dd>

  <dt><strong>[&lt;screens&gt;] copy</strong></dt>
  <dd>Copy url(s) to clipboard. The clipboard contents are formatted in support of <a href="https://www.voidtools.com/faq/#searching">Everything</a>. Does not copy on posix, only print.</dd>

  <dt><strong>extra</strong></dt>
  <dd>Adds an extra screen to the current layout. You can use the *store* command to update the layout beyond this session.</dd>

  <dt><strong>help</strong></dt>
  <dd>Show all commands.</dd>

  <dt><strong>hide &lt;term&gt;</strong></dt>
  <dd>Hide media with term. Future *search* commands will not return hidden files. This can be used to exclude specific file extensions, for example.</dd>

  <dt><strong>idle</strong></dt>
  <dd>Make commands (not) play media. Toggle whether a command is allowed to play media (*idle tag art idle* would update the tag but not play a new file).</dd>

  <dt><strong>[&lt;screens&gt;] kill</strong></dt>
  <dd>Kill screen(s) and chat. Closes the windows and Chatterino, without exiting Cinema (use the *quit* command to kill everything and exit).</dd>

  <dt><strong>layout [&lt;name&gt;]</strong></dt>
  <dd>Change layout to name. Sets up screens and chat.</dd>

  <dt><strong>list</strong></dt>
  <dd>Show all tags.</dd>

  <dt><strong>[&lt;screens&gt;] lock</strong></dt>
  <dd>Lock/unlock screen contents. Toggle whether a screen is allowed to play new files. Would ignore things like *autoplay*, *shuffle*, *tag* if enabled.</dd>

  <dt><strong>macro [&lt;name&gt;]</strong></dt>
  <dd>Execute macro. Processes a macro command by command. Macros are stored in cinema.conf.</dd>

  <dt><strong>[&lt;screen&gt;] maximize</strong></dt>
  <dd>Maximize and close others. Kills all windows except &lt;screen&gt; or first and sets it to fullscreen.</dd>

  <dt><strong>[&lt;screens&gt;] mute</strong></dt>
  <dd>Mute/unmute screen(s). This is a toggle.</dd>

  <dt><strong>quit</strong></dt>
  <dd>Close windows and quit Cinema.</dd>

  <dt><strong>[&lt;screens&gt;] search [&lt;term&gt;]</strong></dt>
  <dd>Limit media to term. Searches through all directories and urls in cinema.conf. Example searches: *C:*, *foo*, *.mp4*, */bar/baz/*.</dd>

  <dt><strong>[&lt;screens&gt;] shuffle</strong></dt>
  <dd>Shuffle media. Plays a new file. This is the default autocomplete command.</dd>

  <dt><strong>store [&lt;layout name&gt;]</strong></dt>
  <dd>Store layout in cinema.conf. Creates or updates the layout in cinema.conf.</dd>

  <dt><strong>[&lt;screen1 screen2&gt;] swap</strong></dt>
  <dd>Swap screen contents. Makes screen 1 play the media of screen 2 and vice versa.</dd>

  <dt><strong>[&lt;screens&gt;] tag [&lt;name&gt;]</strong></dt>
  <dd>Limit media to tag. Tags group media, stored in cinema.conf.</dd>

  <dt><strong>[&lt;screens&gt;] twitch [&lt;name&gt;]</strong></dt>
  <dd>Show channel. Shortcut to watch a specific stream.</dd>
</dl>
