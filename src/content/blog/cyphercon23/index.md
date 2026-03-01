---
title: "CypherCon 2023, Dogteeth, Adventures, and Polyglots"
description: "How we got sandbox privilege escalation on RPi Pico Badges"
date: "2023-04-01"
banner:
  src: "../../../assets/hackedbadge.png"
  alt: "Badge saying 'hello from outside the sandbox!' -SIGPwny"
  caption: 'Breaking out of one sandbox into another.'
categories:
  - "Security"
  - "Writeup"
keywords:
  - "Raspberry Pi Pico"
  - "Embedded Hacking"
  - "Privilege Escalation"
  - "Security"
  - "Polyglot"
---

## CypherCon 2023

This past week I attended [CypherCon 2023](https://CypherCon.com/) with the security club at UIUC, [SIGPwny.](https://SIGPwny.com) It was really fun; I met so many new people and learned a lot of new concepts. If getting to DEFCON is restrictive for someone interested in learning new topics about security & networking, CypherCon is an excellent conference to attend.

One of the long standing traditions over the past 7 years are the badges. You can, of course, get a regular (analog) badge, but the [tymkrs](https://www.tymkrs.com/) always go above and beyond with a really unique digital PCB badge. There are various competitions and challenges that will award you with a "black badge", a special badge that marks your accomplishment at the conference and grants free admission to CypherCon forever. This year, SIGPwny acquired *three*. One for a puzzle scavenger hunt, one for an IoT CTF that we won, and a third for the badge hacking challenge. I worked with [Nate](https://farlow.dev/) to develop a unique exploit on the badges.

## The Badge & The Challenge
<img src="/images/badge.jpg"  width="300" height="400">

The badge this year was deceptively simple. On the outside, it was a E Ink display with a single knob-pushbutton. The knob controlled an RGB LED which you used to navigate the menus. If there was a prompt for red, yellow, green, blue, violet, you could change the LED and navigate to a new page. There were several "apps" on the badge, such as:

- An extremely long and in-depth text based adventure
- A "browser" where users could navigate to various pages and see other users custom pages, harking back to the personal webpages of early-2000s.
- A logo generator, which would make a logo that displays on your badge when it goes to sleep.
- Network Mode, which would transmit your user profile to other badges, allowing others to use your logo when they put their badge into sleep, and view your 'website' in the browser. The badges also said that they transmit other stored users, making a large mesh network within the entire conference.

I cannot express enough how cool it was to interact with these badges. Meeting other people and discovering little secrets was a blast. People had fun with customization and it was really cool to see what others designed. VIPs had a SD card attached to their badge, which included a couple extra tools to use for the badge, and documentation for the various features and other technical details under the hood.

**So what was the challenge this year?**

Impress the Tykmrs (Whisker & Addie). Ok. Yeah. Easy, well defined goals. Nate and I immediately started running through ideas about how we can send our user profile and it doing something "interesting" on the badges when transmitted. We needed to understand more, so we got to digging into the badge's internals.

## The Technical Details
Under the hood, the badge was a Raspberry Pi Pico with some extra storage, attached to a secondary board that managed the knob, screen, and LED. The Pico was running Micropython, meaning we could connect to the board and access its filesystem with tools like `rshell` or `minicom` and spin up a REPL to interact with the board directly. Micropython is custom made for embedded hardware that isn't a full SoC, like the RP2020 chip and so on.

We wanted to get our hands on that extra documentation and tools, so I conscripted [David](https://davidan.dev/) to find a VIP and get them to allow us to make a copy... he did within 5 minutes. I have provided an archive of the badge's internals and documentation & tools on [Github](https://github.com/Surg-Dev/CypherCon-badge-archive).

At this point, we were able to discover a few things:

- The user profile contains the data for the custom logo, information about the user's adventure progress, and the custom website information. It has a header which contains magic bytes, version information and other settings for the file.
- Transmitted user profiles get stored in a `cache` folder until they are complete, which then get copied over to a `users` folder.
- User profiles are transmitted with an incrementing version number, allowing updates to propagate throughout the badges.
- There is a custom programming language built for the badge called Dogteeth, a markdown-like, self-modifying language that is used for the browser and adventure game
- The adventure game has a Turing Complete feature set of Dogteeth, allowing you to define conditions, jump around, read and set variables and trackers.
- The browser had a subset of Dogteeth, only able to really read values, but also had the ability to load an adventure and move out of the browser context to the adventure context.

## Breaking the Browser
We wanted to dig a little deeper about the Dogteeth `warp` command. It was enabled in the browser, which trivially is "unsafe" if you are able to load any file as an adventure. It was barely documented, but the code for the browser showed that it supported this feature. The warp command was implemented like so:

```python
# Snippet of the warp(world_name) command in adventure.py
print('starting badge adventure mode')
world_file = world_name + '.static'
print('serial#' + str(player_id) + ' world|' + world_file + '|')
load_world('world/' + world_file)
```
We have control of that `world_name` variable. It's unsanitized, and in theory, we could get directory traversal and open any file on the Pico. Normally, appending that `'.static'` would ruin most tricks we could do. Python strings don't treat null characters the same way as C does, even in CPython. If I call `open` in a Python REPL:

```
>>> f = open("README.md\x00.md")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: embedded null byte
>>> 
```

Nate told me that strings are handled as such, but he noted that the implementation of MicroPython with Little Filesystem (LFS) might be different. So we tried to the same thing in the badge. Note that in Dogteeth, functions are preceded with a `$`:

```
$warp(cube.static\x00)
```

This was in a file called `custom.tcisite`. If you uploaded this file to the badge, then invoked the uploader tool in the menu of the badge, it updates your user profile with your custom website. Note that the null byte is there for readability, the actual file had a null byte pasted in, there's no escaping/parsing of hex characters. If the badge crashed when opening our browser page, this technique is consistent with regular Python. However, sure enough, it loaded into the "cube" adventure that was on the badge. Micropython's implementation of `open` doesn't catch null bytes, and when it calls the C version of `open`, it will null terminate the string!

## Transmission Woes
We thought we could get away with two user files. Our user file, which the custom website is a single warp command that goes to another user file (User 699, as that was the last user that would transmit over the badge). However, unfortunately the transmission during the conference was not very fast or reliable.

To really test it out, We collected all the badges that SIGPwny members had got, and left it in our hotel room, overnight, transmitting. We never observed the badges transmitting a user other than its own, and complete transfers didn't always happen. The badges make a default user once it starts building a cache for that user, but we never had it update the site for a specific user.

<img src="/images/badgematrix.jpg"  width="300" height="400">

We later learned that there was a bit more error checking, and the badge won't accept malformed user files. We need something robust and self-contained. We also needed something guaranteed to work if you have our file. The 2 file approach doesn't work if you only have one of the files transmitted.

## Constructing the Polyglot
What we needed is a file that when opened in the browser context warps to itself in the adventure context, and then runs some interesting code. This is otherwise known as a "Polyglot program", as we're working with two different "versions" of Dogteeth. 

The `custom.tcisite` we used is the following (nullbytes shown): `$warp(../users/ID.tciuser\x00)` (where ID is our specific badge ID). At the very least, if you went to our browser page, the badge would promptly crash, as it called itself. Now, we needed to make the entire `.tciuser` file a valid Dogteeth program. We needed to set up a very specific start to the program.

Dogteeth programs have the following specification: Line 1 is the very first line executed/printed. Line 2 is used for the instruction pointer. Line 3 is used for the runtime clock. Dogteeth repeatably (and sometimes recursively) parses functions until it is plain text, at which point it prints it to the screen.

The `.tciuser` file specification is fairly simple: The first 16 bytes are the magic bytes of the file, confirming its a `.tciuser` file and some version/data settings. The next 976 bytes is the logo data for that user, otherwise known as a `.tcipage` file. The first 16 bytes of this block, again, is used as magic bytes and information about the logo. The next 960 bytes is raw data for the logo to draw specific glyphs that was in the custom font. The rest of the file are user variables used in the adventure, a total of 2KB, and the custom `.tcisite` which is 5KB long.

The documentation lies here, and says that the options bytes in the header are unused by the badge. However, the badge will not load a user file if it has invalid row/column information or a data mode above 2. We used one of the tools (leinnet) that was on the VIP SD card to make an empty logo, but a valid `.tcipage` file. 

I realized that I could make it so that the 32 bytes of header information was valid Dogteeth, since there were no newline bytes. Instead of our user file having a neat logo, it had Dogteeth code. So after the header, I added a space, and inserted the line `$wget(.entry)`. Dogteeth will get the line of code under the .entry header. I then modified the hex of the logo to act as the valid 3 lines of Dogteeth that I needed, then we made a little message to confirm we were working in the adventure context:

<div class="iframe-container"><iframe loading="lazy" src="https://www.youtube.com/embed/v7oWCvBq2r0"></iframe></div>

It ended up working! Now, any user who gets our user file and visits our browser page will be warped to our own custom adventure game, located entirely within the same user file. Note that we can make Dogteeth access a point much later in the file. So our custom webpage can also contain valid "full-context" Dogteeth after it warps. This gives us just shy of 6KB of room to make a interesting adventure.

## The Worm
Nate also discovered that we could make our user files effectively worms, and transmit it to the whole conference. Since we had full access to "environment" variables and the related software we could accomplish the following:

- We can spoof any User ID and send as other badges that were not our own. This was a method to guarantee that we could fill other badges with every user, if the mesh networking truly did not work, given enough time.
- We can broadcast a user profile with the highest revision number, preventing a user from broadcasting a new update to their own profile.

In theory, we could've made our polyglot adventure profile for every user ID, broadcast it at the highest revision number in the conference, and make everyone's browser go to a custom adventure game.

We of course, did *not* do this, due to the transmission irregularities and the somewhat destructive nature of this exploit to everyone's badges.

## Conclusion
We unfortunately couldn't find if there was a file read/write exploit within Dogteeth. At no point does the Dogteeth interpreter opens a file with write permissions. If so, we could've completely rewritten the software on everyone's badges. Maybe one exists, and I might personally try to tinker with a few ideas. One of the ideas bounced around was to use the fact that the Pico had two cores to do some multiprocessing. The networking mode locks your badge while it transmits data, you technically could put it on the second core and always be transmitting without the badge being in the obvious network mode. There's a lot to do, and I hope to explore various mods with the device.

This was the "coolest thing" that someone did with the badges, according to Whisker, scoring us a black badge. Unfortunately, massive storms were rolling in the Chicago area, and we had to get back to Chambana ASAP, skipping the awards ceremony. Hopefully, we'll talk about this exploit in person at next year's CypherCon. That being said, it was a ton of fun regardless. SIGPwny runs a CTF in the Fall for students interested in security. We're going to try and make our own (much simpler) badges to give to students to interact and tinker with.

### Socials

**Follow Nate:** [Site](https://farlow.dev/) | [Twitter](https://twitter.com/0x1337cafe)

**Follow Sam:** [Site](https://surg.dev) | [Twitter](https://twitter.com/Sam_Ruggerio)

**Follow SIGPwny:** [Site](https://SIGPwny.com) | [Twitter](https://twitter.com/SIGPwny)

If you're interested in helping SIGPwny teach students security & run cool events, [please email us](mailto:hello@sigpwny.com)


