---
title: "GrimmCTF at Thotcon 0xC"
description: "God has cursed me for my hubris and my work is never finished"
date: "2023-05-20"
banner:
  src: "gauges.png"
  alt: ""
  caption: ''
categories:
  - "Security"
  - "Writeup"
keywords:
  - "Web"
  - "Python"
  - "Metasploit"
  - "Log4j"
---

Grimm ran a CTF at Thotcon 0xC this year. I competed and took first! I've included writeups for everything. I'm doing these writeups from memory, so there's a severe lack of detail, but the high level idea and concepts should still be there.

## Python Programming 1-3
Each of these challenges were a netcat connection to a program that asked 3 questions under a time limit. The time limit was generous enough that you could do each of these manually, but you probably should still write a small script to make the answers (like converting hex or base 64).

The final question of the 3rd part gave you a hex value, and asked you to return it back in little-endian *as raw bytes*. This can't be done easily as your clipboard will often use UTF-8 and everything goes south. The VMs we were required to use didn't have pwntools, so you have to open the netcat connection manually:

```py
import socket

def netcat(hostname, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    while 1:
        # Send data
        s.sendall(b"data")
        #receive data
        data = s.recv(1024)
        if len(data) == 0:
            break
        print("Received:", repr(data))
    print("Connection closed.")
    s.close()
```

You can send and receive and manage what question you're in via `find` calls and the like.

For the little endian problem in question, this line solves it:

```py
hex_string = 'cafebabe'
s.sendall(bytes(bytearray.fromhex(hex_string)[::-1]))
```

## Raptor Island Website 1-3

#### Part 1
The challenge gives us a range of IPs to check for this hidden service. After a bit of enumeration you find the website on `192.168.125.202`.

#### Part 2
We then need to run `nmap` on this service, and we find an open FTP port which we can connect to via `netcat`. We see that it's running `ProFTPD 1.3.5`

#### Part 3
Googling "ProFTPD 1.3.5 Exploit" leads us to [this script](https://www.exploit-db.com/exploits/49908) on exploit-db.com. We can copy the script and run it on our target to find flag.txt on the system: `TCx23{c3db20a2-d984-11ed-a55f-bf9209ae22f2}`.

## Axxen Baldez 1-3

#### Part 1
We can run a `nmap` scan on the given IP to find a series of open ports (in the 20k port range, specifically). On Port 20433 we have a Zimbra service which is extremely out of date. In the challenge title, XXE was capitalized, so the best guess here is some XML External Entity Injection exploit.

Sure enough, there's an XXE exploit for zimbra on metasploit: `zimbra_xxe_rce`. We configure the exploit, and run it to get a reverse shell. On `/` there is `flag.txt` to get our answer: `TCx23{0941a2d8-d985-11ed-9b09-c74e870c5524}`

#### Part 2
Now we are on the "intranet" of this fake oil company. We need to find a connected device on the local network `172.23.0.0/24`. Unfortunately, our system does not have ping, or nmap, or anything to make life easy. We didn't even have a text editor which frustrated me to no end. But we do have echo and netcat. We are told that this service we're trying to find is on port `5000`.

Netcat has a flag `-z` to just check if a connection accepts. We can use the `-v` flag to have nc output this to stdout. So we write a simple bash script to enumerate IPs on the network:

```sh
echo "for ip in 172.23.0.{3..255} do echo \$ip; nc -zv \$ip 5000; done"
```

We find our service at `172.23.0.8`, which we can `curl` for: `curl 172.23.0.8:5000`. In a comment, we're given the flag: `TCx23{10700734-d985-11ed-aaba-5701d434d094}`

#### Part 3
If you've noticed, all the IPs are local. I had to log in to a VM to access the challenge environment (which is fine), but I didn't trust VPNing into the challenge environment, so I was stuck with web-based RDP and SSH. At this point, I have my laptop, which is RDPing into a Kali VM, which is running a reverse shell into another device on this local network, to then send curl requests to a fourth device to get this webpage that I found. I just wanted to access this browser page like a normal person.

Regardless, we have a page with some slider inputs in form elements, which are disabled. The goal is to set all these sliders to a value above 90 (so, 100). Each of the forms made a `POST` request to `/details`. Trying to spoof updating the sliders through curl requests did not make any progress.

The next thing to do is to check `robots.txt`, and a `/admin` page was disabled from it. Viewing the `admin` page gave us a page that tried to redirect us to `:5555`, but that port is closed off. Spoofing the HTTP Host header to be port `5555` also did not work.
However, in the form elements that include this slider gauge, there were also two hidden inputs, `searchHost` and `searchValue`. This would normally redirect to individual pages for each gauge `/portWater`, for example.

However, we can perform SSRF and change the host to `searchHost=localhost:5555` and `searchValue=admin`. This can be wrapped into the cURL request: `curl -H "Content-Type: application/x-www-form-urlencoded" -d "searchHost=http%3A%2F%2Flocalhost%3A5555%2F&searchValue=admin&gaugeValue=100" -X POST 172.23.0.8:5000/details`

Now, we get an admin page, where the sliders now have a js script attached to them:

```html
<input class="slider" type="range" id="gaugeValue-portwaterGauge" name="gaugeValue" min="0" max="100" value="21"
             oninput="updateGauge('portwaterGauge', 0, 100);" onchange="updateGauge('portwaterGauge', 0, 100);"></input>
```

and the script:
```js
<script>
  function updateGauge(id, min, max) {
      const newGaugeDisplayValue = document.getElementById("gaugeValue-" + id).value;
      const newGaugeValue = Math.floor(((newGaugeDisplayValue - min) / (max - min)) * 100);

      const requestUrl = '/change?id=' + id + '&value=' + newGaugeValue
      fetch(requestUrl, {
        method: 'POST',
      }).then(function (response) {
          return response;
      }).then(function (response) {
          window.location.replace("/admin");
      });

      document.getElementById(id).style.setProperty('--gauge-display-value', newGaugeDisplayValue);
      document.getElementById(id).style.setProperty('--gauge-value', newGaugeValue);
  }
</script>
```

This makes a POST request to `/change`, so now we can set each of the gauges to 100. We can make a POST request from the index page as the `:5555` host, which makes a search value form element of `change`, like so:

```sh
curl -H "Content-Type: application/x-www-form-urlencoded" -d "searchHost=http%3A%2F%2Flocalhost%3A5555%2F&searchValue=change?id=portwaterGauge%26value=100&gaugeValue=100" -X POST 172.23.0.8:5000/details
```

We do this for each of the gauges, and on the third one, we were given a flag! `TCx23{176b18bc-d985-11ed-ab51-7754c5f93cb8}`


## Alarming Development
We're given a page that has a `/logs` page and a `/login` page which, if logged in as an admin, allows you to access `/status`.
In the logs, we see that it tracks when an admin logs into the service, and compares the credentials against environment variables. We also see that this service is running Java on the backend, and hasn't been updated since Novemeber of 2021, when log4shell and the major log4j vulnerabilities dropped.

As an aside, my favorite log4j exploit was one that downloaded onto the victim's system a patch for the log4j vuln, thus being a vaccine exploit!

All things aside, the other thing to note about `/logs` is that it prints out the `User-Agent` header of any visitor of the page. We're pretty much set up for a straightforward log4j exploit.

We don't need a reverse shell here, we can exfil the environment variables using metasploit's `log4shell_scanner` We put in that we want the `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables. We get this information and log into the admin panel, and on the status page there is a switch that turns off the alarm system (this page), and gives us the flag: `TCx23{f32d0898-d984-11ed-b8c7-13e026e913bf}`

## You can see the penguin
This was the only crypto challenge, and was not solved by anyone at the end of the CTF. I had the right approach, but didn't execute it (and stopped working on this CTF) in the last few hours. I only came up with the right execution about 30 minutes after the CTF closed. I'm including the theoretical approach, since I rarely do crypto and it's one of the few attacks available for this encryption scheme.

We're given a page titled "Enter Commands Below", which allows us to input two commands in text boxes, and go to the next page. It says that it will use "Military-Grade" encryption to send the commands to the backend. The next page, titled "Explicitly Confirm Batch" shows the exact JSON object that gets encrypted, it's in the format: `{"command1": "yourinput1", "command2": "yourinput2", "root": false}`.

Then, on the third page, titled "Executing Commands Bravely", you get the output of your two commands. There are only three supported ones: `help, whoami, flag`. `flag` can only be run as root, `help` tells you those three commands, and `whoami` says either `nobody` or `root`. The backend server is Python, but I don't think this has anything to do with pyjail techniques. Any input that's not those three will just fail with an generic "invalid command" message.

Googling "Military-Grade" tells us that the phrase is referring to AES-256. The headers to each page abbreviate to ECB, and the challenge title "You can see the penguin" probably refers to the ECB penguin as the prototypical example to showing the weakness to ECB encryption. So the encryption scheme is AES-256 in ECB mode. On the confirm page, there's a hidden input form of the AES encryption of the JSON object. We can confirm it's AES by sending a bunch of As as one of our inputs and seeing repetition in the ciphertext. This also told me that the key is fixed, and there is either a fixed IV or none at all, since it doesn't change on multiple attempts.

Even though we can generate as much ciphertext with controlled plaintext, AES basically prevents us from recovering the key. Since we know what is being encrypted, a padding attack doesn't actually do us any good. The only thing we know is that we can determine is what 16 characters correspond to 16 bytes of cipher text. This is because ECB splits the plaintext into 16 byte blocks and encrypts each individually, with no seeding from other blocks.

Let's consider an example:

```js
{"command1": "yourinput1", "command2": "yourinput2", "root": false}
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```
Every character within a 0-f block gets encrypted individually. This means we can isolate what plaintext gets encrypted, and replace the block with something that we know before we send it to the backend. The example below runs the `flag` command, but also isolates `false}` into it's own block!

```js
{"command1": "flag", "command2": "abc", "root": false}
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

We can get the ciphertext of the 4th block this object:

```js
{"command1": "flag", "command2": "              true           }", "root": false}
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef...
```

Now, we have the corresponding ciphertext to `true           }`. On the confirm page, when you hit submit it makes a POST request with the ciphertext. We can use the Burp Proxy browser to intercept this request, and modify the ciphertext as we see fit.

We can first get the ciphertext to:
```js
{"command1": "flag", "command2": "abc", "root": false}
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

and replace the 4th block with the one we made earlier to build the ciphertext corresponding to this object:
```js
{"command1": "flag", "command2": "abc", "root": true           }
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

My original approach tried to replace the entire `"root": false` with `"root": true`. Double quotes and slashes get escaped, and encrypted with the added slashes, so I kept running in circles. The approach described above *should* work, but I came up with it just slightly after the deadline... oh well!
